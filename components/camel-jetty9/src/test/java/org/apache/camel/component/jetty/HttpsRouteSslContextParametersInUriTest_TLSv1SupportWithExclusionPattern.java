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

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import javax.crypto.Cipher;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import org.apache.camel.Exchange;
import org.apache.camel.Message;
import org.apache.camel.Processor;
import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.component.jetty9.JettyHttpComponent9;
import org.apache.camel.component.mock.MockEndpoint;
import org.apache.camel.impl.JndiRegistry;
import org.apache.camel.util.jsse.FilterParameters;
import org.apache.camel.util.jsse.KeyManagersParameters;
import org.apache.camel.util.jsse.KeyStoreParameters;
import org.apache.camel.util.jsse.SSLContextClientParameters;
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

public class HttpsRouteSslContextParametersInUriTest_TLSv1SupportWithExclusionPattern extends HttpsRouteTest {

    private KeyManagersParameters kmp;

    @Override
    protected JndiRegistry createRegistry() throws Exception {
        KeyStoreParameters ksp = new KeyStoreParameters();
        ksp.setResource(this.getClass().getClassLoader().getResource("jsse/localhost.ks").toString());
        ksp.setPassword(pwd);

        KeyManagersParameters kmp = new KeyManagersParameters();
        kmp.setKeyPassword(pwd);
        kmp.setKeyStore(ksp);
        this.kmp = kmp;

        SSLContextParameters sslContextParameters = new SSLContextParameters();
        sslContextParameters.setKeyManagers(kmp);

        List<String> supportedSslProtocols = Arrays.asList("TLSv1", "TLSv1.1");
        SecureSocketProtocolsParameters protocolsParameters = new SecureSocketProtocolsParameters();
        protocolsParameters.setSecureSocketProtocol(supportedSslProtocols);
        sslContextParameters.setSecureSocketProtocols(protocolsParameters);

        FilterParameters cipherParameters = new FilterParameters();
        cipherParameters.getInclude().add(".*");
        List<String> excludedCiphers = cipherParameters.getExclude();
        excludedCiphers.add("^.*_(MD5|SHA1)$");
        excludedCiphers.add("^.*_DHE_.*$");
        excludedCiphers.add("^.*_3DES_.*$");
        sslContextParameters.setCipherSuitesFilter(cipherParameters);

        JndiRegistry registry = super.createRegistry();
        registry.bind("sslContextParameters", sslContextParameters);

        return registry;
    }

    @Test
    public void testHelloEndpoint() throws Exception {
        // these tests does not run well on Windows
        if (isPlatform("windows")) {
            return;
        }

//        Thread.sleep(200000L);

        HostnameVerifier hv = new HostnameVerifier() {
            public boolean verify(String urlHostName, SSLSession session) {
                log.warn("Warning: URL Host: " + urlHostName + " vs. " + session.getPeerHost());
                return true;
            }
        };

        // Create a trust manager that does not validate certificate chains
        TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                log.info("getAcceptedIssuers: {}", new X509Certificate[0]);
                return new X509Certificate[0];
            }

            public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {
                log.info("checkClientTrusted for certs {} and authType: {}", certs, authType);
            }

            public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {
                log.info("checkServerTrusted for certs {} and authType: {}", certs, authType);
            }

        } };

        URL url = new URL("https://localhost:" + port1 + "/hello");

//        TrustManager tm[] = { new SSLPinningTrustManager(kmp.getKeyStore().createKeyStore()) };
        SSLContext sslContext = SSLContext.getInstance("TLSv1");
        sslContext.init(null, trustAllCerts, new SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(new PreferredCipherSuiteSSLSocketFactory(sslContext.getSocketFactory()));
        HttpsURLConnection.setDefaultHostnameVerifier(hv);

        HttpsURLConnection con = (HttpsURLConnection)url.openConnection();

        con.connect();

        print_https_cert(con);
        String data = read_content(con);

        assertEquals("<b>Hello World</b>", data);

        con.disconnect();
    }

    public static class PreferredCipherSuiteSSLSocketFactory extends SSLSocketFactory {

        private static final List<String> PREFERRED_CIPHER_SUITES = Arrays.asList(
                // TLS v1/1.1 ciphers
                "TLS_RSA_WITH_AES_128_CBC_SHA",
                "TLS_RSA_WITH_AES_256_CBC_SHA",
                "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
                "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
                "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
                "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
                "TLS_DH_anon_WITH_AES_128_CBC_SHA",
                "TLS_DH_anon_WITH_AES_256_CBC_SHA",
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
                "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
                // TLS v1.2 ciphers
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
        );

        private final SSLSocketFactory delegate;

        public PreferredCipherSuiteSSLSocketFactory(SSLSocketFactory delegate) {

            this.delegate = delegate;
        }

        @Override
        public String[] getDefaultCipherSuites() {

            return setupPreferredDefaultCipherSuites(this.delegate);
        }

        @Override
        public String[] getSupportedCipherSuites() {

            return setupPreferredSupportedCipherSuites(this.delegate);
        }

        @Override
        public Socket createSocket(String arg0, int arg1) throws IOException {

            Socket socket = this.delegate.createSocket(arg0, arg1);
            String[] cipherSuites = setupPreferredDefaultCipherSuites(delegate);
            ((SSLSocket)socket).setEnabledCipherSuites(cipherSuites);

            return socket;
        }

        @Override
        public Socket createSocket(InetAddress arg0, int arg1) throws IOException {

            Socket socket = this.delegate.createSocket(arg0, arg1);
            String[] cipherSuites = setupPreferredDefaultCipherSuites(delegate);
            ((SSLSocket)socket).setEnabledCipherSuites(cipherSuites);

            return socket;
        }

        @Override
        public Socket createSocket(Socket arg0, String arg1, int arg2, boolean arg3)
                throws IOException {

            Socket socket = this.delegate.createSocket(arg0, arg1, arg2, arg3);
            String[] cipherSuites = setupPreferredDefaultCipherSuites(delegate);
            ((SSLSocket)socket).setEnabledCipherSuites(cipherSuites);

            return socket;
        }

        @Override
        public Socket createSocket(String arg0, int arg1, InetAddress arg2, int arg3)
                throws IOException {

            Socket socket = this.delegate.createSocket(arg0, arg1, arg2, arg3);
            String[] cipherSuites = setupPreferredDefaultCipherSuites(delegate);
            ((SSLSocket)socket).setEnabledCipherSuites(cipherSuites);

            return socket;
        }

        @Override
        public Socket createSocket(InetAddress arg0, int arg1, InetAddress arg2,
                                   int arg3) throws IOException {

            Socket socket = this.delegate.createSocket(arg0, arg1, arg2, arg3);
            String[] cipherSuites = setupPreferredDefaultCipherSuites(delegate);
            ((SSLSocket)socket).setEnabledCipherSuites(cipherSuites);

            return socket;
        }

        private static String[] setupPreferredDefaultCipherSuites(SSLSocketFactory sslSocketFactory) {

            String[] defaultCipherSuites = sslSocketFactory.getDefaultCipherSuites();

            ArrayList<String> suitesList = new ArrayList<>(PREFERRED_CIPHER_SUITES);
            suitesList.addAll(Arrays.asList(defaultCipherSuites));

            return suitesList.toArray(new String[suitesList.size()]);
        }

        private static String[] setupPreferredSupportedCipherSuites(SSLSocketFactory sslSocketFactory) {

            String[] supportedCipherSuites = sslSocketFactory.getSupportedCipherSuites();

            ArrayList<String> suitesList = new ArrayList<>(PREFERRED_CIPHER_SUITES);
            suitesList.addAll(Arrays.asList(supportedCipherSuites));

            return suitesList.toArray(new String[suitesList.size()]);
        }
    }

    /**
     * A custom X509TrustManager implementation that trusts a specified server certificate in addition
     * to those that are in the system TrustStore.
     * Also handles an out-of-order certificate chain, as is often produced by Apache's mod_ssl
     */
    public static class SSLPinningTrustManager implements X509TrustManager {

        private final TrustManager[] originalTrustManagers;
        private final KeyStore trustStore;

        /**
         * @param trustStore A KeyStore containing the server certificate that should be trusted
         * @throws NoSuchAlgorithmException
         * @throws KeyStoreException
         */
        public SSLPinningTrustManager(KeyStore trustStore) throws NoSuchAlgorithmException, KeyStoreException {
            this.trustStore = trustStore;

            final TrustManagerFactory originalTrustManagerFactory = TrustManagerFactory.getInstance("X509");
            originalTrustManagerFactory.init(trustStore);

            originalTrustManagers = originalTrustManagerFactory.getTrustManagers();
        }

        /**
         * No-op. Never invoked by client, only used in server-side implementations
         * @return
         */
        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }

        /**
         * No-op. Never invoked by client, only used in server-side implementations
         * @return
         */
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws java.security.cert.CertificateException {
            System.err.println("Check client trusted");
        }


        /**
         * Given the partial or complete certificate chain provided by the peer,
         * build a certificate path to a trusted root and return if it can be validated and is trusted
         * for client SSL authentication based on the authentication type. The authentication type is
         * determined by the actual certificate used. For instance, if RSAPublicKey is used, the authType should be "RSA".
         * Checking is case-sensitive.
         * Defers to the default trust manager first, checks the cert supplied in the ctor if that fails.
         * @param chain the server's certificate chain
         * @param authType the authentication type based on the client certificate
         * @throws java.security.cert.CertificateException
         */
        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws java.security.cert.CertificateException {
            System.err.println("Check server trusted");
            try {
                for (TrustManager originalTrustManager : originalTrustManagers) {
                    ((X509TrustManager) originalTrustManager).checkServerTrusted(chain, authType);
                }
            } catch(CertificateException originalException) {
                try {
                    // Ordering issue?
                    X509Certificate[] reorderedChain = reorderCertificateChain(chain);
                    if (! Arrays.equals(chain, reorderedChain)) {
                        checkServerTrusted(reorderedChain, authType);
                        return;
                    }
                    for (int i = 0; i < chain.length; i++) {
                        if (validateCert(reorderedChain[i])) {
                            return;
                        }
                    }
                    throw originalException;
                } catch(Exception ex) {
                    ex.printStackTrace();
                    throw originalException;
                }
            }

        }

        /**
         * Checks if we have added the certificate in the trustStore, if that's the case we trust the certificate
         * @param x509Certificate the certificate to check
         * @return true if we know the certificate, false otherwise
         * @throws KeyStoreException on problems accessing the key store
         */
        private boolean validateCert(final X509Certificate x509Certificate) throws KeyStoreException {
            return trustStore.getCertificateAlias(x509Certificate) != null;
        }

        /**
         * Puts the certificate chain in the proper order, to deal with out-of-order
         * certificate chains as are sometimes produced by Apache's mod_ssl
         * @param chain the certificate chain, possibly with bad ordering
         * @return the re-ordered certificate chain
         */
        private X509Certificate[] reorderCertificateChain(X509Certificate[] chain) {

            X509Certificate[] reorderedChain = new X509Certificate[chain.length];
            List<X509Certificate> certificates = Arrays.asList(chain);

            int position = chain.length - 1;
            X509Certificate rootCert = findRootCert(certificates);
            reorderedChain[position] = rootCert;

            X509Certificate cert = rootCert;
            while((cert = findSignedCert(cert, certificates)) != null && position > 0) {
                reorderedChain[--position] = cert;
            }

            return reorderedChain;
        }

        /**
         * A helper method for certificate re-ordering.
         * Finds the root certificate in a possibly out-of-order certificate chain.
         * @param certificates the certificate change, possibly out-of-order
         * @return the root certificate, if any, that was found in the list of certificates
         */
        private X509Certificate findRootCert(List<X509Certificate> certificates) {
            X509Certificate rootCert = null;

            for(X509Certificate cert : certificates) {
                X509Certificate signer = findSigner(cert, certificates);
                if(signer == null || signer.equals(cert)) { // no signer present, or self-signed
                    rootCert = cert;
                    break;
                }
            }

            return rootCert;
        }

        /**
         * A helper method for certificate re-ordering.
         * Finds the first certificate in the list of certificates that is signed by the sigingCert.
         */
        private X509Certificate findSignedCert(X509Certificate signingCert, List<X509Certificate> certificates) {
            X509Certificate signed = null;

            for(X509Certificate cert : certificates) {
                Principal signingCertSubjectDN = signingCert.getSubjectDN();
                Principal certIssuerDN = cert.getIssuerDN();
                if(certIssuerDN.equals(signingCertSubjectDN) && !cert.equals(signingCert)) {
                    signed = cert;
                    break;
                }
            }

            return signed;
        }

        /**
         * A helper method for certificate re-ordering.
         * Finds the certificate in the list of certificates that signed the signedCert.
         */
        private X509Certificate findSigner(X509Certificate signedCert, List<X509Certificate> certificates) {
            X509Certificate signer = null;

            for(X509Certificate cert : certificates) {
                Principal certSubjectDN = cert.getSubjectDN();
                Principal issuerDN = signedCert.getIssuerDN();
                if(certSubjectDN.equals(issuerDN)) {
                    signer = cert;
                    break;
                }
            }

            return signer;
        }
    }

    private void print_https_cert(HttpsURLConnection con){
        if(con!=null) {
            try {
                System.out.println("Response Code : " + con.getResponseCode());
                System.out.println("Cipher Suite : " + con.getCipherSuite());
                System.out.println("\n");

                Certificate[] certs = con.getServerCertificates();
                for(Certificate cert : certs){
                    System.out.println("Cert Type : " + cert.getType());
                    System.out.println("Cert Hash Code : " + cert.hashCode());
                    System.out.println("Cert Public Key Algorithm : "
                                       + cert.getPublicKey().getAlgorithm());
                    System.out.println("Cert Public Key Format : "
                                       + cert.getPublicKey().getFormat());
                    System.out.println("\n");
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private String read_content(HttpsURLConnection con){
        StringBuilder response = new StringBuilder();
        if(con!=null){
            try (BufferedReader br = new BufferedReader(new InputStreamReader(con.getInputStream()))) {
                String input;
                while ((input = br.readLine()) != null) {
                    response.append(input);
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return response.toString();
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
        log.debug("TLSv1");

        try (CloseableHttpClient tlsv1Client = initiateClient("TLSv1")) {
            sendBodyAndHeader(tlsv1Client, getHttpProducerScheme() + "localhost:" + port1 + "/test", expectedBody, "Content-Type", "application/xml");
        } catch (IOException | GeneralSecurityException ex) {
            fail("Could not initiate TLS v1 capable HTTP client");
        }

        // TLS v1.1
        log.debug("TLSv1.1");

        try (CloseableHttpClient tlsv11Client = initiateClient("TLSv1.1")) {
            sendBodyAndHeader(tlsv11Client, getHttpProducerScheme() + "localhost:" + port2 + "/test", expectedBody, "Content-Type", "application/xml");
        } catch (IOException | GeneralSecurityException ex) {
            ex.printStackTrace();
            fail("Could not initiate TLS v1.1 capable HTTP client");
        }

        // TLS v1.2
        log.debug("TLSv1.2");

        try (CloseableHttpClient tlsv12Client = initiateClient("TLSv1.2")) {
            sendBodyAndHeader(tlsv12Client, getHttpProducerScheme() + "localhost:" + port1 + "/test", expectedBody, "Content-Type", "application/xml");
            fail("Should have thrown an exception as TLS v1.2 is not supported");
        } catch (NoSuchAlgorithmException | KeyManagementException ex) {
            fail("Could not initiate TLS v1.2 capable HTTP client");
        } catch (Exception ex) {
            assertIsInstanceOf(SSLHandshakeException.class, ex);
        }
    }

    protected CloseableHttpClient initiateClient(String protocol) throws IOException, GeneralSecurityException {

        // https://www.openssl.org/docs/man1.0.2/apps/ciphers.html
        String[] tlsv1Ciphers = {
//                "TLS_RSA_WITH_NULL_MD5",
//                "TLS_RSA_WITH_NULL_SHA",
//                "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
//                "TLS_RSA_WITH_RC4_128_MD5",
//                "TLS_RSA_WITH_RC4_128_SHA",
//                "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
//                "TLS_RSA_WITH_IDEA_CBC_SHA",
//                "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
//                "TLS_RSA_WITH_DES_CBC_SHA",
//                "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
//                "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",
//                "TLS_DH_DSS_WITH_DES_CBC_SHA",
//                "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",
//                "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA",
//                "TLS_DH_RSA_WITH_DES_CBC_SHA",
//                "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA",
//                "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
//                "TLS_DHE_DSS_WITH_DES_CBC_SHA",
//                "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
//                "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
//                "TLS_DHE_RSA_WITH_DES_CBC_SHA",
//                "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
//                "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5",
//                "TLS_DH_anon_WITH_RC4_128_MD5",
//                "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
//                "TLS_DH_anon_WITH_DES_CBC_SHA",
//                "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
                // AES siphersuites from RFC3268, extending TLS v1.0
                "TLS_RSA_WITH_AES_128_CBC_SHA",
                "TLS_RSA_WITH_AES_256_CBC_SHA",
//                "TLS_DH_DSS_WITH_AES_128_CBC_SHA",
//                "TLS_DH_DSS_WITH_AES_256_CBC_SHA",
//                "TLS_DH_RSA_WITH_AES_128_CBC_SHA",
//                "TLS_DH_RSA_WITH_AES_256_CBC_SHA",
                "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
                "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
                "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
                "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
                "TLS_DH_anon_WITH_AES_128_CBC_SHA",
                "TLS_DH_anon_WITH_AES_256_CBC_SHA",
                // Camellia ciphersuites from RFC4132, extending TLS v1.0
//                "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
//                "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
//                "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA",
//                "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA",
//                "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA",
//                "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA",
//                "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA",
//                "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA",
//                "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
//                "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
//                "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA",
//                "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA",
                // SEED ciphersuites from RFC4162, extending TLS v1.0
//                "TLS_RSA_WITH_SEED_CBC_SHA",
//                "TLS_DH_DSS_WITH_SEED_CBC_SHA",
//                "TLS_DH_RSA_WITH_SEED_CBC_SHA",
//                "TLS_DHE_DSS_WITH_SEED_CBC_SHA",
//                "TLS_DHE_RSA_WITH_SEED_CBC_SHA",
//                "TLS_DH_anon_WITH_SEED_CBC_SHA",
                // GOST ciphersuites from draft-chudov-cryptopro-cptls, extending TLS v1.0
//                "TLS_GOSTR341094_WITH_28147_CNT_IMIT",
//                "TLS_GOSTR341001_WITH_28147_CNT_IMIT",
//                "TLS_GOSTR341094_WITH_NULL_GOSTR3411",
//                "TLS_GOSTR341001_WITH_NULL_GOSTR3411",
                // Additional Export 1024 and other cipher suites
//                "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA",
//                "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA",
//                "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA",
//                "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHAn",
//                "TLS_DHE_DSS_WITH_RC4_128_SHA",
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
//                "TLS_DH_RSA_WITH_AES_128_CBC_SHA256",
//                "TLS_DH_RSA_WITH_AES_256_CBC_SHA256",
//                "TLS_DH_RSA_WITH_AES_128_GCM_SHA256",
//                "TLS_DH_RSA_WITH_AES_256_GCM_SHA384",
//                "TLS_DH_DSS_WITH_AES_128_CBC_SHA256",
//                "TLS_DH_DSS_WITH_AES_256_CBC_SHA256",
//                "TLS_DH_DSS_WITH_AES_128_GCM_SHA256",
//                "TLS_DH_DSS_WITH_AES_256_GCM_SHA384",
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

        SSLContext sslContext =
                SSLContexts.custom().useProtocol(protocol).build();
        SSLConnectionSocketFactory scsf = new SSLConnectionSocketFactory(sslContext, new String[] {protocol},
                                                                         "TLSv1.2".equals(protocol) ? tlsv12Ciphers : tlsv1Ciphers,
                                                                         new NoopHostnameVerifier());
        return HttpClients.custom().setSSLSocketFactory(scsf).build();
    }

    protected void sendBodyAndHeader(HttpClient client, String uri, String expectedBody, String header, String headerValue) throws IOException {
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
