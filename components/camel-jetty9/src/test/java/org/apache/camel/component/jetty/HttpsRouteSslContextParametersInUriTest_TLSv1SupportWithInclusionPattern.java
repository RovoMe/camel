/**
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.camel.component.jetty;

import java.io.IOException;
import java.net.URISyntaxException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import javax.crypto.Cipher;
import javax.net.ssl.SSLContext;
import org.apache.camel.Exchange;
import org.apache.camel.Message;
import org.apache.camel.Processor;
import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.component.jetty9.JettyHttpComponent9;
import org.apache.camel.component.mock.MockEndpoint;
import org.apache.camel.impl.JndiRegistry;
import org.apache.camel.util.jsse.CipherSuitesParameters;
import org.apache.camel.util.jsse.KeyManagersParameters;
import org.apache.camel.util.jsse.KeyStoreParameters;
import org.apache.camel.util.jsse.SSLContextParameters;
import org.apache.camel.util.jsse.SecureSocketProtocolsParameters;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;
import org.junit.Test;

public class HttpsRouteSslContextParametersInUriTest_TLSv1SupportWithInclusionPattern extends HttpsRouteTest {
    
    @Override
    protected JndiRegistry createRegistry() throws Exception {
        KeyStoreParameters ksp = new KeyStoreParameters();
        ksp.setResource(this.getClass().getClassLoader().getResource("jsse/localhost.ks").toString());
        ksp.setPassword(pwd);

        KeyManagersParameters kmp = new KeyManagersParameters();
        kmp.setKeyPassword(pwd);
        kmp.setKeyStore(ksp);

        SSLContextParameters sslContextParameters = new SSLContextParameters();
        sslContextParameters.setKeyManagers(kmp);

        List<String> supportedSslProtocols = Arrays.asList("TLSv1", "TLSv1.1");
        SecureSocketProtocolsParameters protocolsParameters = new SecureSocketProtocolsParameters();
        protocolsParameters.setSecureSocketProtocol(supportedSslProtocols);
        sslContextParameters.setSecureSocketProtocols(protocolsParameters);

        // FIXME: by default Jetty will filter away any ciphers that match any of these patterns:
        //     .*_NULL_.*, .*_anon_.*, .*_EXPORT_.*, .*_DES_.*
        // which currently leaves non available even on explicitly setting one
        List<String> supportedCiphers = Arrays.asList("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
                                                      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
                                                      "TLS_RSA_WITH_AES_128_CBC_SHA",
                                                      "TLS_RSA_WITH_AES_256_CBC_SHA",
                                                      "TLS_ECDH_anon_WITH_NULL_SHA",
                                                      "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
                                                      "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
                                                      "TLS_DH_anon_WITH_AES_256_CBC_SHA",
                                                      "TLS_DH_anon_WITH_AES_128_CBC_SHA",
                                                      "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
                                                      "TLS_ECDH_anon_WITH_AES_256_CBC_SHA");
        CipherSuitesParameters cipherSuites = new CipherSuitesParameters();
        cipherSuites.setCipherSuite(supportedCiphers);
        sslContextParameters.setCipherSuites(cipherSuites);

        JndiRegistry registry = super.createRegistry();
        registry.bind("sslContextParameters", sslContextParameters);

        return registry;
    }

    @Test
    @Override
    public void testEndpoint() throws Exception {
        // these tests does not run well on Windows
        if (isPlatform("windows")) {
            return;
        }

        // Java cryptographic extension (JCE) is probably not installed so skipp the test
        if (2147483647 > Cipher.getMaxAllowedKeyLength("AES")) {
            log.warn("Skipping test as JCE is not available");
            return;
        }

        MockEndpoint mockEndpointA = resolveMandatoryEndpoint("mock:a", MockEndpoint.class);
        MockEndpoint mockEndpointB = resolveMandatoryEndpoint("mock:b", MockEndpoint.class);
        mockEndpointA.expectedBodiesReceived(expectedBody);
        mockEndpointB.expectedBodiesReceived(expectedBody);

        invokeHttpEndpoint();

        mockEndpointA.assertIsSatisfied();
        List<Exchange> list = mockEndpointA.getReceivedExchanges();
        Exchange exchange = list.get(0);
        assertNotNull("exchange", exchange);

        Message in = exchange.getIn();
        assertNotNull("in", in);

        Map<String, Object> headers = in.getHeaders();

        log.info("Headers: " + headers);

        assertTrue("Should be more than one header but was: " + headers, headers.size() > 0);
    }

    @Override
    protected void invokeHttpEndpoint() throws IOException {

        // TLS v1

        try (CloseableHttpClient tlsv1Client = initiateClient("TLSv1")) {
            sendBodyAndHeader(tlsv1Client, getHttpProducerScheme() + "localhost:" + port1 + "/test", expectedBody, "Content-Type", "application/xml");
        } catch (NoSuchAlgorithmException | KeyManagementException ex) {
            fail("Could not initiate TLS v1.0 capable HTTP client");
        }

        // TLS v1.1

        try (CloseableHttpClient tlsv11Client = initiateClient("TLSv1.1")) {
            sendBodyAndHeader(tlsv11Client, getHttpProducerScheme() + "localhost:" + port2 + "/test", expectedBody, "Content-Type", "application/xml");
        } catch (NoSuchAlgorithmException | KeyManagementException ex) {
            fail("Could not initiate TLS v1.1 capable HTTP client");
        }

        // TLS v1.2

        try (CloseableHttpClient tlsv12Client = initiateClient("TLSv1.2")) {
            sendBodyAndHeader(tlsv12Client, getHttpProducerScheme() + "localhost:" + port1 + "/test", expectedBody, "Content-Type", "application/xml");
            fail("Should have thrown an exception as TLS v1.2 is not supported");
        } catch (NoSuchAlgorithmException | KeyManagementException ex) {
            fail("Could not initiate TLS v1.2 capable HTTP client");
        } catch (Exception ex) {
            assertIsInstanceOf(IOException.class, ex);
        }
    }

    protected CloseableHttpClient initiateClient(String protocol) throws NoSuchAlgorithmException,
            KeyManagementException {
        // https://www.openssl.org/docs/man1.0.2/apps/ciphers.html
        String[] tlsv1Ciphers = {
                // AES siphersuites from RFC3268, extending TLS v1.0
                "TLS_RSA_WITH_AES_128_CBC_SHA",
                "TLS_RSA_WITH_AES_256_CBC_SHA",
                "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
                "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
                "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
                "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
                "TLS_DH_anon_WITH_AES_128_CBC_SHA",
                "TLS_DH_anon_WITH_AES_256_CBC_SHA",
                // Elliptic curve cipher suites
                "TLS_ECDH_RSA_WITH_NULL_SHA",
                "TLS_ECDH_RSA_WITH_RC4_128_SHA",
                "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
                "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
                "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
                "TLS_ECDH_ECDSA_WITH_NULL_SHA",
                "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
                "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
                "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
                "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
                "TLS_ECDHE_RSA_WITH_NULL_SHA",
                "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
                "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
                "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
                "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
                "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
                "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
                "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
                "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
                "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
                "TLS_ECDH_anon_WITH_NULL_SHA",
                "TLS_ECDH_anon_WITH_RC4_128_SHA",
                "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",
                "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
                "TLS_ECDH_anon_WITH_AES_256_CBC_SHA"
        };

        // Plenty of ciphers are listed at https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
        String[] tlsv12Ciphers = {
                "TLS_RSA_WITH_NULL_SHA256",
                "TLS_RSA_WITH_AES_128_CBC_SHA256",
                "TLS_RSA_WITH_AES_256_CBC_SHA256",
                "TLS_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
                "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
                "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
                "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
                "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
                "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
                "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
                "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
                "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
                "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
                "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                "TLS_DH_anon_WITH_AES_128_CBC_SHA256",
                "TLS_DH_anon_WITH_AES_256_CBC_SHA256",
                "TLS_DH_anon_WITH_AES_128_GCM_SHA256",
                "TLS_DH_anon_WITH_AES_256_GCM_SHA384"
        };

        SSLContext sslContext = SSLContexts.custom().useProtocol(protocol).build();
        SSLConnectionSocketFactory scsf = new SSLConnectionSocketFactory(sslContext, new String[] {protocol},
                                                                         "TLSv1.2".equals(protocol) ? tlsv12Ciphers : tlsv1Ciphers,
                                                                         new NoopHostnameVerifier());
        return HttpClients.custom().setSSLSocketFactory(scsf).build();
    }

    protected void sendBodyAndHeader(HttpClient client, String uri, String expectedBody, String header, String headerValue) throws
            IOException {
        HttpPost postOp = new HttpPost(uri);
        postOp.addHeader(header, headerValue);
        postOp.setEntity(new StringEntity(expectedBody));

        client.execute(postOp);
    }

    @Override
    protected RouteBuilder createRouteBuilder() throws Exception {
        return new RouteBuilder() {
            public void configure() throws URISyntaxException
            {
                JettyHttpComponent jetty = getContext().getComponent("jetty", JettyHttpComponent9.class);
                // NOTE: These are here to check that they are properly ignored.
                setSSLProps(jetty, "", "asdfasdfasdfdasfs", "sadfasdfasdfas");

                from("jetty:https://localhost:" + port1 + "/test?sslContextParameters=#sslContextParameters").to("mock:a");
                from("jetty:https://localhost:" + port2 + "/test?sslContextParameters=#sslContextParameters").to("mock:b");

                Processor proc = (Exchange exchange) -> exchange.getOut().setBody("<b>Hello World</b>");
                from("jetty:https://localhost:" + port1 + "/hello?sslContextParameters=#sslContextParameters").process(proc);

            }
        };
    }
}
