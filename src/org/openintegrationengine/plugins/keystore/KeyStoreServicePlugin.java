/*
 * SPDX-License-Identifier: MPL-2.0
 */
package org.openintegrationengine.plugins.keystore;

import com.mirth.connect.model.Channel;
import com.mirth.connect.model.ExtensionPermission;
import com.mirth.connect.model.ServerEventContext;
import com.mirth.connect.plugins.ChannelPlugin;
import com.mirth.connect.plugins.ServicePlugin;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openintegrationengine.plugins.keystore.provider.BitwardenCrypto;

import java.util.Map;
import java.util.Properties;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Lifecycle for the key store.
 *
 * <p>The first refresh runs at start, before anything is deployed, and then on a timer.
 * Both halves matter: a channel that deploys before its credential has been fetched
 * resolves {@code ${keystore.x}} to the literal text, and a credential rotated in the
 * vault at noon has to reach a running engine without anyone restarting it.
 *
 * <p>Also a {@link ChannelPlugin}, which is not decoration. Deploying every channel calls
 * the engine's {@code clearGlobalMap()} between the undeploy and the deploy, so the
 * published secrets are wiped part-way through a "Redeploy All". The deploy hooks put them
 * back, and they run before any channel deploys. One class implements both interfaces
 * because the extension controller tests the same object against each in turn, so it is
 * registered as a service plugin and a channel plugin from a single entry in plugin.xml.
 *
 * <p>That registration has a consequence worth knowing about: the controller adds the
 * object to its list of server plugins once per interface it matches, and then starts
 * every entry in that list. So {@link #init}, {@link #start} and {@link #stop} are each
 * called twice for this class. They are guarded accordingly -- without it there would be
 * two refresh schedulers, doubling the traffic to every vault and leaking one of them at
 * shutdown, which is not the sort of thing that shows up until a vault starts rate
 * limiting.
 */
public class KeyStoreServicePlugin implements ServicePlugin, ChannelPlugin {

    public static final String PLUGIN_POINT_NAME = "Key Store";

    private static final Logger LOG = LogManager.getLogger(KeyStoreServicePlugin.class);

    private static volatile KeyStoreService service;

    /** Guards the doubled lifecycle calls described above. */
    private static final AtomicBoolean STARTED = new AtomicBoolean(false);

    private static volatile ScheduledExecutorService scheduler;

    public static KeyStoreService service() {
        return service;
    }

    public static SecretResolver resolver() {
        KeyStoreService current = service;
        return current == null ? null : current.resolver();
    }

    @Override
    public void init(Properties properties) {
        if (service == null) {
            service = new KeyStoreService(new SecretResolver());
        }
    }

    @Override
    public void start() {
        if (!STARTED.compareAndSet(false, true)) {
            return;
        }
        // Checked once, at start, rather than on each use. A JRE that cannot reproduce
        // Bitwarden's key derivation would decrypt to plausible rubbish rather than fail,
        // and a wrong password handed to a channel is much worse than a refusal here.
        String cryptoFault = BitwardenCrypto.selfTest();
        if (cryptoFault != null) {
            LOG.error("key store: Bitwarden key derivation is not working on this JRE ({}). "
                + "Bitwarden connections will not be usable; the other providers are "
                + "unaffected.", cryptoFault);
        }

        int interval = KeyStoreStore.refreshIntervalSeconds();

        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "key-store-refresh");
            // Daemon so an in-flight vault call cannot hold up engine shutdown.
            t.setDaemon(true);
            return t;
        });

        // No initial delay, unlike the volume monitor: that one waits for channels to
        // finish deploying because counting them early is meaningless, whereas this one
        // has to have finished before they deploy or their credentials will not resolve.
        //
        // Fixed delay rather than fixed rate: a pass across several vaults can outlast the
        // interval, and queueing another behind it would turn one slow vault into a
        // growing backlog of identical work.
        scheduler.scheduleWithFixedDelay(this::pass, 0, interval, TimeUnit.SECONDS);

        LOG.info("key store started: {} binding(s) across {} vault(s), refreshing every {}s, "
            + "published as ${{}.<name>}",
            KeyStoreStore.bindings().size(), KeyStoreStore.connections().size(),
            interval, KeyStoreStore.namespace());
    }

    /**
     * One refresh pass.
     *
     * <p>Never allowed to throw. An exception escaping a scheduled task cancels every
     * future run, which would leave secrets frozen at whatever they were when it happened
     * -- working, and then silently not rotating, which is the worst of both.
     */
    private void pass() {
        KeyStoreService current = service;
        if (current == null) {
            return;
        }
        try {
            current.resolver().refresh();
        } catch (Throwable t) {
            LOG.error("key store refresh failed", t);
        }
    }

    @Override
    public void stop() {
        if (!STARTED.compareAndSet(true, false)) {
            return;
        }
        if (scheduler != null) {
            scheduler.shutdownNow();
            scheduler = null;
        }
        KeyStoreService current = service;
        if (current != null) {
            // Explicitly cleared rather than left to the JVM exiting. On a plugin reload
            // the process continues, and leaving the previous set published would keep
            // serving values from a configuration that is no longer loaded.
            current.resolver().unpublish();
        }
        service = null;
    }

    @Override
    public void update(Properties properties) {
        // Connections and bindings are read from the configuration table on every pass, so
        // there is nothing to reload. The interval is the exception: the scheduler fixes
        // its period when it starts, so changing it takes a restart, which the settings
        // response says out loud.
    }

    @Override
    public Properties getDefaultProperties() {
        return new Properties();
    }

    // ------------------------------------------------------------------
    // ChannelPlugin: putting the secrets back after the engine clears them
    // ------------------------------------------------------------------

    /**
     * Before a single channel deploys.
     *
     * <p>The earliest hook there is: the engine calls this inside each channel's deploy
     * task, before the channel itself deploys, so a connector that resolves a field while
     * deploying still sees its credential.
     *
     * <p>Cheap and idempotent. It puts back a map that is already built, and returns
     * immediately when nothing has cleared it -- which is every deploy but the ones that
     * follow a clear.
     */
    @Override
    public void deploy(Channel channel, ServerEventContext context) {
        republish();
    }

    /**
     * Before a batch of channels deploys.
     *
     * <p>This one runs late: the engine calls it immediately <em>after</em> the global
     * deploy script, not before. So on a "Redeploy All" the global deploy script can run
     * while the map is still empty, and it is the one place where {@code ${keystore.name}}
     * may not resolve. Channel connector fields and channel deploy scripts are unaffected,
     * because both come after the per-channel hook above.
     *
     * <p>A global deploy script that needs a secret should call {@link Secrets} instead,
     * which reads what the resolver is holding and never looks at the global map at all.
     */
    @Override
    public void deploy(ServerEventContext context) {
        republish();
    }

    private void republish() {
        SecretResolver resolver = resolver();
        if (resolver == null) {
            return;
        }
        try {
            resolver.republish();
        } catch (Throwable t) {
            // Never allowed to escape. This runs inside the deploy path, and a fault here
            // would fail the deploy of a channel that may not use a secret at all.
            LOG.error("key store: could not restore published secrets during deploy", t);
        }
    }

    /**
     * Undeploy is deliberately not a republish.
     *
     * <p>The engine clears the global map after undeploying everything and before
     * deploying again, so anything put back here would be wiped moments later. The deploy
     * side is the one that matters.
     */
    @Override
    public void undeploy(String channelId, ServerEventContext context) {
        // Nothing to do.
    }

    @Override
    public void undeploy(ServerEventContext context) {
        // Nothing to do.
    }

    /** Saving or removing a channel does not touch the key store. */
    @Override
    public void save(Channel channel, ServerEventContext context) {
        // Nothing to do.
    }

    @Override
    public void remove(Channel channel, ServerEventContext context) {
        // Nothing to do.
    }

    @Override
    public ExtensionPermission[] getExtensionPermissions() {
        return new ExtensionPermission[] {
            new ExtensionPermission(PLUGIN_POINT_NAME, "Manage the key store",
                "Allows viewing and editing vault connections and secret bindings. This "
                + "includes entering vault credentials, so it should be granted as "
                + "narrowly as the permission to edit channels.",
                new String[] {
                    "keyStoreStatus", "keyStoreSummary",
                    "keyStoreGetConnections", "keyStoreSaveConnection",
                    "keyStoreDeleteConnection", "keyStoreTestConnection",
                    "keyStoreGetBindings", "keyStoreSaveBinding", "keyStoreDeleteBinding",
                    "keyStoreRefresh", "keyStoreSetSettings"
                },
                new String[] {})
        };
    }

    @Override
    public String getPluginPointName() {
        return PLUGIN_POINT_NAME;
    }

    @Override
    public Map<String, Object> getObjectsForSwaggerExamples() {
        return Map.of();
    }
}
