package org.carlspring.security.vertx.http;

import io.vertx.core.AbstractVerticle;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.client.WebClient;
import io.vertx.ext.web.client.WebClientOptions;

/**
 * Demonstrates a Server-Side Request Forgery (SSRF) vulnerability (CWE-918).
 * User-controlled input is used to construct an outbound HTTP request target
 * without validation, allowing attackers to probe internal services.
 *
 * @author carlspring
 */
public class SsrfExample
        extends AbstractVerticle
{

    @Override
    public void start()
    {
        Router router = Router.router(vertx);
        WebClient webClient = WebClient.create(vertx, new WebClientOptions().setConnectTimeout(10000));

        router.get("/fetch").handler(ctx -> {
            // User-supplied host and path — SSRF vulnerability
            String host = ctx.request().getParam("host");
            String path = ctx.request().getParam("path");

            // No allowlist check: attacker can supply internal addresses like
            // host=169.254.169.254&path=/latest/meta-data/ (AWS metadata service)
            // or host=localhost&path=/admin
            webClient.get(80, host, path).send(ar -> {
                if (ar.succeeded())
                {
                    ctx.response()
                       .putHeader("Content-Type", "text/plain")
                       .end("Response: " + ar.result().bodyAsString());
                }
                else
                {
                    ctx.response().setStatusCode(502).end("Request failed: " + ar.cause().getMessage());
                }
            });
        });

        vertx.createHttpServer().requestHandler(router).listen(8080);
    }

}
