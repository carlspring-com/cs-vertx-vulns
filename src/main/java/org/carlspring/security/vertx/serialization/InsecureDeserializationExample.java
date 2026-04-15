package org.carlspring.security.vertx.serialization;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.util.Base64;

import io.vertx.core.AbstractVerticle;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.BodyHandler;

/**
 * Demonstrates an insecure deserialization vulnerability (CWE-502).
 * Untrusted, user-controlled data is deserialized using Java's native
 * ObjectInputStream without any class filtering or integrity checks,
 * allowing remote code execution via crafted serialized payloads.
 *
 * @author carlspring
 */
public class InsecureDeserializationExample
        extends AbstractVerticle
{

    @Override
    public void start()
    {
        Router router = Router.router(vertx);
        router.route().handler(BodyHandler.create());

        router.post("/api/deserialize").handler(ctx -> {
            // User-supplied Base64-encoded serialized Java object
            String encoded = ctx.body().asString();

            try
            {
                byte[] serializedData = Base64.getDecoder().decode(encoded);

                // Insecure deserialization: no class filtering, no integrity check
                ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(serializedData));
                Object obj = ois.readObject();
                ois.close();

                ctx.response()
                   .putHeader("Content-Type", "text/plain")
                   .end("Deserialized object type: " + obj.getClass().getName());
            }
            catch (Exception e)
            {
                ctx.response().setStatusCode(400).end("Deserialization failed: " + e.getMessage());
            }
        });

        router.get("/api/session").handler(ctx -> {
            // Session token from cookie deserialized without validation
            String sessionCookie = ctx.request().getCookie("session") != null
                                   ? ctx.request().getCookie("session").getValue()
                                   : null;

            if (sessionCookie != null)
            {
                try
                {
                    byte[] sessionData = Base64.getDecoder().decode(sessionCookie);
                    ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(sessionData));
                    Object session = ois.readObject();
                    ois.close();

                    ctx.response().end("Session user: " + session.toString());
                }
                catch (Exception e)
                {
                    ctx.response().setStatusCode(400).end("Invalid session");
                }
            }
            else
            {
                ctx.response().setStatusCode(401).end("No session");
            }
        });

        vertx.createHttpServer().requestHandler(router).listen(8080);
    }

}
