package org.carlspring.security.vertx.xml;

import java.io.StringReader;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import io.vertx.core.AbstractVerticle;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.BodyHandler;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

/**
 * Demonstrates an XML External Entity (XXE) injection vulnerability (CWE-611).
 * User-supplied XML is parsed without disabling external entity resolution,
 * allowing attackers to read local files or perform SSRF via crafted XML.
 *
 * @author carlspring
 */
public class XxeInjectionExample
        extends AbstractVerticle
{

    @Override
    public void start()
            throws Exception
    {
        Router router = Router.router(vertx);
        router.route().handler(BodyHandler.create());

        router.post("/api/xml").handler(ctx -> {
            String xmlBody = ctx.body().asString();

            try
            {
                // XXE vulnerability: external entities are enabled by default
                DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
                DocumentBuilder builder = factory.newDocumentBuilder();

                // Parsing untrusted XML without disabling external entities
                Document document = builder.parse(new InputSource(new StringReader(xmlBody)));

                String rootElement = document.getDocumentElement().getNodeName();
                ctx.response()
                   .putHeader("Content-Type", "text/plain")
                   .end("Parsed root element: " + rootElement);
            }
            catch (Exception e)
            {
                ctx.response().setStatusCode(400).end("Invalid XML: " + e.getMessage());
            }
        });

        vertx.createHttpServer().requestHandler(router).listen(8080);
    }

}
