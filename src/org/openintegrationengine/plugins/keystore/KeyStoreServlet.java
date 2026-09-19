/*
 * SPDX-License-Identifier: MPL-2.0
 */
package org.openintegrationengine.plugins.keystore;

import com.mirth.connect.client.core.api.MirthApiException;
import com.mirth.connect.server.api.MirthServlet;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Maps {@link KeyStoreService} onto HTTP.
 *
 * <p>A failed operation answers {@code 200} with {@code ok:false} and a readable message
 * rather than a 500 carrying a serialised Java exception. The console renders whatever it
 * is given, and a stack trace in a web page is not an error message -- it is an error
 * message wrapped in something that makes people stop reading.
 *
 * <p>The failure path also matters more here than in most plugins: the exception from a
 * vault call can carry the endpoint and the policy that refused it, and a serialised stack
 * trace would put all of that on a page. {@link #failure} takes the message and nothing
 * else.
 */
public class KeyStoreServlet extends MirthServlet implements KeyStoreServletInterface {

    public KeyStoreServlet(@Context HttpServletRequest request,
                           @Context SecurityContext securityContext) {
        super(request, securityContext, KeyStoreServicePlugin.PLUGIN_POINT_NAME);
    }

    private static KeyStoreService service() {
        KeyStoreService s = KeyStoreServicePlugin.service();
        if (s == null) {
            // Installed, but the ServicePlugin never started: a server fault, not a bad
            // request, so it gets a status that says so.
            throw new MirthApiException(Response.Status.SERVICE_UNAVAILABLE);
        }
        return s;
    }

    private static Map<String, Object> failure(Throwable t) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", Boolean.FALSE);
        String message = t.getMessage();
        out.put("error", message == null || message.isBlank()
            ? t.getClass().getSimpleName() : message);
        return out;
    }

    private static MirthApiException badRequest(String message) {
        return new MirthApiException(Response
            .status(Response.Status.BAD_REQUEST)
            .entity(message)
            .build());
    }

    @Override
    public Map<String, Object> getStatus(boolean refresh) {
        try {
            return service().status(refresh);
        } catch (Exception e) {
            return failure(e);
        }
    }

    @Override
    public Map<String, Object> getSummary() {
        try {
            return service().summary();
        } catch (Exception e) {
            return failure(e);
        }
    }

    @Override
    public Map<String, Object> refresh() {
        try {
            return service().refresh();
        } catch (Exception e) {
            return failure(e);
        }
    }

    @Override
    public Map<String, Object> getConnections() {
        try {
            return service().connections();
        } catch (Exception e) {
            return failure(e);
        }
    }

    @Override
    public Map<String, Object> saveConnection(Map<String, String> connection) {
        try {
            return service().saveConnection(connection);
        } catch (Exception e) {
            return failure(e);
        }
    }

    @Override
    public Map<String, Object> deleteConnection(String id) {
        if (id == null || id.isBlank()) {
            throw badRequest("a connection id is required");
        }
        try {
            return service().deleteConnection(id);
        } catch (Exception e) {
            return failure(e);
        }
    }

    @Override
    public Map<String, Object> testConnection(Map<String, String> connection) {
        try {
            return service().testConnection(connection);
        } catch (Exception e) {
            return failure(e);
        }
    }

    @Override
    public Map<String, Object> getBindings() {
        try {
            return service().bindings();
        } catch (Exception e) {
            return failure(e);
        }
    }

    @Override
    public Map<String, Object> saveBinding(Map<String, String> binding) {
        try {
            return service().saveBinding(binding);
        } catch (Exception e) {
            return failure(e);
        }
    }

    @Override
    public Map<String, Object> deleteBinding(String id) {
        if (id == null || id.isBlank()) {
            throw badRequest("a binding id is required");
        }
        try {
            return service().deleteBinding(id);
        } catch (Exception e) {
            return failure(e);
        }
    }

    @Override
    public Map<String, Object> setSettings(Map<String, String> settings) {
        try {
            return service().saveSettings(settings);
        } catch (Exception e) {
            return failure(e);
        }
    }
}
