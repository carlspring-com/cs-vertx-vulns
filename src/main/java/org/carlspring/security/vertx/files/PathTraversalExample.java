package org.carlspring.security.vertx.files;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

import io.vertx.core.AbstractVerticle;
import io.vertx.ext.web.Router;

/**
 * Demonstrates a path traversal vulnerability (CWE-22).
 * User-controlled input is used directly to construct a file path
 * without sanitization, allowing attackers to read arbitrary files.
 *
 * @author carlspring
 */
public class PathTraversalExample
        extends AbstractVerticle
{

    private static final String BASE_DIR = "/var/app/files";

    @Override
    public void start()
    {
        Router router = Router.router(vertx);

        router.get("/files/:filename").handler(ctx -> {
            // User-controlled filename used directly — path traversal vulnerability
            String filename = ctx.pathParam("filename");

            // No sanitization: attacker can supply "../../etc/passwd"
            File file = new File(BASE_DIR, filename);

            vertx.fileSystem().readFile(file.getAbsolutePath(), result -> {
                if (result.succeeded())
                {
                    ctx.response()
                       .putHeader("Content-Type", "application/octet-stream")
                       .end(result.result());
                }
                else
                {
                    ctx.response().setStatusCode(404).end("File not found");
                }
            });
        });

        router.post("/files/delete").handler(ctx -> {
            String filename = ctx.request().getParam("name");

            // No path validation before deleting
            File target = new File(BASE_DIR + File.separator + filename);
            try
            {
                Files.delete(target.toPath());
                ctx.response().end("Deleted");
            }
            catch (IOException e)
            {
                ctx.response().setStatusCode(500).end("Error deleting file");
            }
        });

        vertx.createHttpServer().requestHandler(router).listen(8080);
    }

}
