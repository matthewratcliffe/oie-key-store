/*
 * SPDX-License-Identifier: MPL-2.0
 */
package org.openintegrationengine.plugins.keystore;

import com.mirth.connect.client.core.ClientException;
import com.mirth.connect.client.core.Operation;
import com.mirth.connect.client.core.api.BaseServletInterface;
import com.mirth.connect.client.core.api.MirthOperation;
import com.mirth.connect.client.core.api.Param;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;

import java.util.Map;

/**
 * REST surface for the key store.
 *
 * <p>Registered under {@code /api/keystore}. Everything returns a map, and every list
 * inside one is a list of tab-separated strings -- see the note on {@link KeyStoreService}
 * for why that is not just laziness.
 *
 * <p>No response carries a secret value or a stored credential. The write operations are
 * audited ({@code auditable} is left at its default) because entering a vault credential is
 * exactly the kind of change that should appear in the engine's event log with a user
 * against it; the read operations are not, because the console polls them.
 */
@Path("/keystore")
@Consumes({MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON})
@Produces({MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON})
public interface KeyStoreServletInterface extends BaseServletInterface {

    /**
     * The state of every binding.
     *
     * <p>{@code refresh=false} reports the last scheduled pass, which costs nothing. The
     * page uses that on load and {@code refresh=true} only when someone asks, because each
     * refresh is a network call per binding out to a cloud vault.
     */
    @GET
    @Path("/status")
    @io.swagger.v3.oas.annotations.Operation(summary = "State of every secret binding.")
    @MirthOperation(name = "keyStoreStatus", display = "Get key store status",
        auditable = false)
    Map<String, Object> getStatus(
        @Param("refresh")
        @io.swagger.v3.oas.annotations.Parameter(description =
            "Read from the vaults now instead of reporting the last scheduled pass.")
        @QueryParam("refresh") boolean refresh) throws ClientException;

    /**
     * Fault count only.
     *
     * <p>Exists for the navigation badge, which is drawn on every page load: it must not
     * be the reason the console feels slow, so it never contacts a vault.
     */
    @GET
    @Path("/summary")
    @io.swagger.v3.oas.annotations.Operation(summary = "Fault count, without reading vaults.")
    @MirthOperation(name = "keyStoreSummary", display = "Get key store summary",
        auditable = false)
    Map<String, Object> getSummary() throws ClientException;

    /** Reads every binding from its vault now. */
    @POST
    @Path("/refresh")
    @io.swagger.v3.oas.annotations.Operation(summary = "Re-read every secret now.")
    @MirthOperation(name = "keyStoreRefresh", display = "Refresh secrets",
        type = Operation.ExecuteType.ASYNC)
    Map<String, Object> refresh() throws ClientException;

    // ------------------------------------------------------------------
    // Connections
    // ------------------------------------------------------------------

    /** Configured vaults. Never includes a stored credential. */
    @GET
    @Path("/connections")
    @io.swagger.v3.oas.annotations.Operation(summary = "List vault connections.")
    @MirthOperation(name = "keyStoreGetConnections", display = "List vault connections",
        auditable = false)
    Map<String, Object> getConnections() throws ClientException;

    /**
     * Creates a vault connection, or updates the one named by {@code id}.
     *
     * <p>Takes a map body rather than query parameters: a connection has up to seventeen
     * fields and one of them is a credential, which has no business in a URL that ends up
     * in an access log. The body must be XStream-shaped
     * ({@code <map><entry><string>k</string><string>v</string></entry></map>}); a plain
     * JSON object is rejected by the engine's deserialiser with a 500.
     *
     * <p>A credential field that is absent or empty leaves the stored one alone. Send
     * {@code clearCredential=true} to remove it.
     */
    @POST
    @Path("/connections")
    @io.swagger.v3.oas.annotations.Operation(summary = "Create or update a vault connection.")
    @MirthOperation(name = "keyStoreSaveConnection", display = "Save a vault connection",
        type = Operation.ExecuteType.ASYNC)
    Map<String, Object> saveConnection(
        @Param("connection")
        @io.swagger.v3.oas.annotations.Parameter(description =
            "Connection fields. Unsupplied keys are left as they were.", required = true)
        Map<String, String> connection) throws ClientException;

    @POST
    @Path("/connections/_delete")
    @io.swagger.v3.oas.annotations.Operation(summary = "Delete a vault connection.")
    @MirthOperation(name = "keyStoreDeleteConnection", display = "Delete a vault connection",
        type = Operation.ExecuteType.ASYNC)
    Map<String, Object> deleteConnection(
        @Param("id")
        @io.swagger.v3.oas.annotations.Parameter(description = "Connection id.", required = true)
        @QueryParam("id") String id) throws ClientException;

    /**
     * Authenticates to a vault and reports what it could see.
     *
     * <p>Takes the whole connection rather than an id so an unsaved one can be tested,
     * which is the moment it is most worth testing. With an id and a blank credential, the
     * stored credential is used.
     */
    @POST
    @Path("/connections/_test")
    @io.swagger.v3.oas.annotations.Operation(summary = "Test a vault connection.")
    @MirthOperation(name = "keyStoreTestConnection", display = "Test a vault connection",
        type = Operation.ExecuteType.ASYNC)
    Map<String, Object> testConnection(
        @Param("connection")
        @io.swagger.v3.oas.annotations.Parameter(description =
            "Connection fields to test, saved or not.", required = true)
        Map<String, String> connection) throws ClientException;

    // ------------------------------------------------------------------
    // Bindings
    // ------------------------------------------------------------------

    /** Variable names and the secrets behind them. Never includes a value. */
    @GET
    @Path("/bindings")
    @io.swagger.v3.oas.annotations.Operation(summary = "List secret bindings.")
    @MirthOperation(name = "keyStoreGetBindings", display = "List secret bindings",
        auditable = false)
    Map<String, Object> getBindings() throws ClientException;

    @POST
    @Path("/bindings")
    @io.swagger.v3.oas.annotations.Operation(summary = "Create or update a secret binding.")
    @MirthOperation(name = "keyStoreSaveBinding", display = "Save a secret binding",
        type = Operation.ExecuteType.ASYNC)
    Map<String, Object> saveBinding(
        @Param("binding")
        @io.swagger.v3.oas.annotations.Parameter(description =
            "Binding fields. Unsupplied keys are left as they were.", required = true)
        Map<String, String> binding) throws ClientException;

    @POST
    @Path("/bindings/_delete")
    @io.swagger.v3.oas.annotations.Operation(summary = "Delete a secret binding.")
    @MirthOperation(name = "keyStoreDeleteBinding", display = "Delete a secret binding",
        type = Operation.ExecuteType.ASYNC)
    Map<String, Object> deleteBinding(
        @Param("id")
        @io.swagger.v3.oas.annotations.Parameter(description = "Binding id.", required = true)
        @QueryParam("id") String id) throws ClientException;

    // ------------------------------------------------------------------
    // Settings
    // ------------------------------------------------------------------

    @POST
    @Path("/settings")
    @io.swagger.v3.oas.annotations.Operation(summary = "Update key store settings.")
    @MirthOperation(name = "keyStoreSetSettings", display = "Set key store settings",
        type = Operation.ExecuteType.ASYNC)
    Map<String, Object> setSettings(
        @Param("settings")
        @io.swagger.v3.oas.annotations.Parameter(description =
            "namespace, refreshIntervalSeconds, serveStaleOnFailure and writeServerEvents.",
            required = true)
        Map<String, String> settings) throws ClientException;
}
