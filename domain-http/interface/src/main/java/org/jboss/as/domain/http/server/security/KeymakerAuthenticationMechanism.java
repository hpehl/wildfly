/*
 * Copyright 2012 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jboss.as.domain.http.server.security;

import static io.undertow.UndertowLogger.REQUEST_LOGGER;
import static io.undertow.UndertowMessages.MESSAGES;
import static io.undertow.security.impl.DigestAuthorizationToken.parseHeader;
import static io.undertow.util.Headers.DIGEST;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import io.undertow.security.api.AuthenticationMechanism;
import io.undertow.security.api.NonceManager;
import io.undertow.security.api.SecurityContext;
import io.undertow.security.idm.Account;
import io.undertow.security.idm.IdentityManager;
import io.undertow.security.impl.DigestAlgorithm;
import io.undertow.security.impl.DigestAuthorizationToken;
import io.undertow.server.HttpServerExchange;
import io.undertow.util.AttachmentKey;
import io.undertow.util.HeaderMap;
import io.undertow.util.Headers;
import io.undertow.util.HexConverter;
import io.undertow.util.HttpString;

/**
 * {@link AuthenticationMechanism} to handle the custom Keymaker authentication. Keymaker is based on a simplified
 * version of digest authentication. Unlike digest authentication the client side is not managed at the browser but
 * the application level. The main motivation for Keymaker is to solve problems with browser based authentication
 * mechanisms - like basic or digest - and CORS.
 *
 * <p>Keymaker basically uses the same algorithms like digest authentication, but relies on other HTTP header and
 * status codes in order to not interfere with digest authentication.</p>
 *
 * @author <a href="mailto:hpehl@redhat.com">Harald Pehl</a>
 */
public class KeymakerAuthenticationMechanism implements AuthenticationMechanism {

    public static final String X_AUTHORIZATION_STRING = "X-Authorization";
    public static final HttpString X_AUTHORIZATION = new HttpString(X_AUTHORIZATION_STRING);
    public static final String X_WWW_AUTHENTICATE_STRING = "X-WWW-Authenticate";
    public static final HttpString X_WWW_AUTHENTICATE = new HttpString(X_WWW_AUTHENTICATE_STRING);
    public static final int KEYMAKER_UNAUTHORIZED = 491;

    private static final String MECHANISM_NAME = "KEYMAKER";
    private static final String KEYMAKER_PREFIX = "Keymaker ";
    private static final int PREFIX_LENGTH = KEYMAKER_PREFIX.length();
    private static final byte COLON = ':';
    private static final Charset UTF_8 = Charset.forName("UTF-8");
    private static final DigestAlgorithm ALGORITHM = DigestAlgorithm.MD5;

    private static final Set<DigestAuthorizationToken> MANDATORY_REQUEST_TOKENS;

    static {
        Set<DigestAuthorizationToken> mandatoryTokens = new HashSet<>();
        mandatoryTokens.add(DigestAuthorizationToken.USERNAME);
        mandatoryTokens.add(DigestAuthorizationToken.REALM);
        mandatoryTokens.add(DigestAuthorizationToken.NONCE);
        mandatoryTokens.add(DigestAuthorizationToken.DIGEST_URI);
        mandatoryTokens.add(DigestAuthorizationToken.RESPONSE);

        MANDATORY_REQUEST_TOKENS = Collections.unmodifiableSet(mandatoryTokens);
    }

    private final String realmName; // TODO - Will offer choice once backing store API/SPI is in.
    private final String domain;
    private final byte[] realmBytes;
    private final NonceManager nonceManager;

    // Where do session keys fit? Do we just hang onto a session key or keep visiting the user store to check if the password
    // has changed?
    // Maybe even support registration of a session so it can be invalidated?

    public KeymakerAuthenticationMechanism(final String realmName, final String domain,
            final NonceManager nonceManager) {
        this.realmName = realmName;
        this.domain = domain;
        this.realmBytes = realmName.getBytes(UTF_8);
        this.nonceManager = nonceManager;
    }

    public AuthenticationMechanismOutcome authenticate(final HttpServerExchange exchange,
            final SecurityContext securityContext) {
        List<String> authHeaders = exchange.getRequestHeaders().get(X_AUTHORIZATION);
        if (authHeaders != null) {
            for (String current : authHeaders) {
                if (current.startsWith(KEYMAKER_PREFIX)) {
                    String digestChallenge = current.substring(PREFIX_LENGTH);

                    try {
                        KeymakerContext context = new KeymakerContext();
                        Map<DigestAuthorizationToken, String> parsedHeader = parseHeader(digestChallenge);
                        context.setParsedHeader(parsedHeader);
                        // Some form of Digest authentication is going to occur so get the DigestContext set on the exchange.
                        exchange.putAttachment(KeymakerContext.ATTACHMENT_KEY, context);

                        return runDigest(exchange, securityContext);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }

                // By this point we had a header we should have been able to verify but for some reason
                // it was not correctly structured.
                return AuthenticationMechanismOutcome.NOT_AUTHENTICATED;
            }
        }

        // No suitable header has been found in this request,
        return AuthenticationMechanismOutcome.NOT_ATTEMPTED;
    }

    @Override
    public ChallengeResult sendChallenge(final HttpServerExchange exchange, final SecurityContext securityContext) {
        sendChallengeHeaders(exchange);
        return new ChallengeResult(true, KEYMAKER_UNAUTHORIZED);
    }


    public AuthenticationMechanismOutcome runDigest(HttpServerExchange exchange, final SecurityContext securityContext) {
        KeymakerContext context = exchange.getAttachment(KeymakerContext.ATTACHMENT_KEY);
        Map<DigestAuthorizationToken, String> parsedHeader = context.getParsedHeader();
        // Step 1 - Verify the set of tokens received to ensure valid values.
        Set<DigestAuthorizationToken> mandatoryTokens = new HashSet<>(MANDATORY_REQUEST_TOKENS);

        // Check all mandatory tokens are present.
        mandatoryTokens.removeAll(parsedHeader.keySet());
        if (mandatoryTokens.size() > 0) {
            for (DigestAuthorizationToken currentToken : mandatoryTokens) {
                // TODO - Need a better check and possible concatenate the list of tokens - however
                // even having one missing token is not something we should routinely expect.
                REQUEST_LOGGER.missingAuthorizationToken(currentToken.getName());
            }
            // TODO - This actually needs to result in a HTTP 400 Bad Request response and not a new challenge.
            return AuthenticationMechanismOutcome.NOT_AUTHENTICATED;
        }

        // Perform some validation of the remaining tokens.
        if (!realmName.equals(parsedHeader.get(DigestAuthorizationToken.REALM))) {
            REQUEST_LOGGER.invalidTokenReceived(DigestAuthorizationToken.REALM.getName(),
                    parsedHeader.get(DigestAuthorizationToken.REALM));
            // TODO - This actually needs to result in a HTTP 400 Bad Request response and not a new challenge.
            return AuthenticationMechanismOutcome.NOT_AUTHENTICATED;
        }

        // TODO - Validate the URI

        MessageDigest digest;
        // Step 2 - Based on the headers received verify that in theory the response is valid.
        try {
            digest = ALGORITHM.getMessageDigest();
        } catch (NoSuchAlgorithmException e) {
            // This is really not expected but the API makes us consider it.
            REQUEST_LOGGER.exceptionProcessingRequest(e);
            return AuthenticationMechanismOutcome.NOT_AUTHENTICATED;
        }

        byte[] ha1;


        final String userName = parsedHeader.get(DigestAuthorizationToken.USERNAME);
        final IdentityManager identityManager = securityContext.getIdentityManager();
        final Account account = identityManager.getAccount(userName);
        if (account == null) {
            //the user does not exist.
            securityContext.authenticationFailed(MESSAGES.authenticationFailed(userName), MECHANISM_NAME);
            return AuthenticationMechanismOutcome.NOT_AUTHENTICATED;
        }

        // Step 2.1 Calculate H(A1)
        try {
            // This is the most simple form of a hash involving the username, realm and password.
            ha1 = createHA1(userName.getBytes(UTF_8), account, digest);
            if(ha1 == null) {
                //the underlying account could not provide the necessary information for DIGEST auth
                return AuthenticationMechanismOutcome.NOT_ATTEMPTED;
            }
        } catch (AuthenticationException e) {
            // Most likely the user does not exist.
            securityContext.authenticationFailed(MESSAGES.authenticationFailed(userName), MECHANISM_NAME);
            return AuthenticationMechanismOutcome.NOT_AUTHENTICATED;
        }

        byte[] ha2;
        // Step 2.2 Calculate H(A2)
        ha2 = createHA2Auth(exchange, digest, parsedHeader);

        byte[] requestDigest;
        requestDigest = createRFC2069RequestDigest(ha1, ha2, digest, parsedHeader);

        byte[] providedResponse = parsedHeader.get(DigestAuthorizationToken.RESPONSE).getBytes(UTF_8);
        if (!MessageDigest.isEqual(requestDigest, providedResponse)) {
            // TODO - We should look at still marking the nonce as used, a failure in authentication due to say a failure
            // looking up the users password would leave it open to the packet being replayed.
            REQUEST_LOGGER.authenticationFailed(parsedHeader.get(DigestAuthorizationToken.USERNAME), DIGEST.toString());
            securityContext.authenticationFailed(MESSAGES.authenticationFailed(userName), MECHANISM_NAME);
            return AuthenticationMechanismOutcome.NOT_AUTHENTICATED;
        }

        // We have authenticated the remote user.

        securityContext.authenticationComplete(account, MECHANISM_NAME);
        return AuthenticationMechanismOutcome.AUTHENTICATED;
    }

    private byte[] createHA1(final byte[] userName, final Account account, final MessageDigest digest)
            throws AuthenticationException {
        char[] attribute = (char[]) account.getAttribute(Account.PLAINTEXT_PASSWORD_ATTRIBUTE);
        if(attribute == null) {
            return null;
        }
        byte[] password = new String(attribute).getBytes(UTF_8);

        try {
            digest.update(userName);
            digest.update(COLON);
            digest.update(realmBytes);
            digest.update(COLON);
            digest.update(password);

            return HexConverter.convertToHexBytes(digest.digest());
        } finally {
            digest.reset();
        }
    }

    private byte[] createHA2Auth(final HttpServerExchange exchange, final MessageDigest digest, Map<DigestAuthorizationToken, String> parsedHeader) {
        byte[] method = exchange.getRequestMethod().toString().getBytes(UTF_8);
        byte[] digestUri = parsedHeader.get(DigestAuthorizationToken.DIGEST_URI).getBytes(UTF_8);

        try {
            digest.update(method);
            digest.update(COLON);
            digest.update(digestUri);

            return HexConverter.convertToHexBytes(digest.digest());
        } finally {
            digest.reset();
        }
    }

    private byte[] createRFC2069RequestDigest(final byte[] ha1, final byte[] ha2, final MessageDigest digest, Map<DigestAuthorizationToken, String> parsedHeader) {
        byte[] nonce = parsedHeader.get(DigestAuthorizationToken.NONCE).getBytes(UTF_8);

        try {
            digest.update(ha1);
            digest.update(COLON);
            digest.update(nonce);
            digest.update(COLON);
            digest.update(ha2);

            return HexConverter.convertToHexBytes(digest.digest());
        } finally {
            digest.reset();
        }
    }

    public void sendChallengeHeaders(final HttpServerExchange exchange) {

        StringBuilder rb = new StringBuilder(KEYMAKER_PREFIX);
        rb.append(Headers.REALM.toString()).append("=\"").append(realmName).append("\",");
        rb.append(Headers.DOMAIN.toString()).append("=\"").append(domain).append("\",");
        rb.append(Headers.NONCE.toString()).append("=\"").append(nonceManager.nextNonce(null, exchange));

        String theChallenge = rb.toString();
        HeaderMap responseHeader = exchange.getResponseHeaders();
        responseHeader.add(X_WWW_AUTHENTICATE, theChallenge);
    }


    private static class KeymakerContext {

        static final AttachmentKey<KeymakerContext> ATTACHMENT_KEY = AttachmentKey.create(KeymakerContext.class);

        Map<DigestAuthorizationToken, String> parsedHeader;

        Map<DigestAuthorizationToken, String> getParsedHeader() {
            return parsedHeader;
        }

        void setParsedHeader(Map<DigestAuthorizationToken, String> parsedHeader) {
            this.parsedHeader = parsedHeader;
        }
    }

    private class AuthenticationException extends Exception {

        private static final long serialVersionUID = 4123187263595319747L;

        // TODO - Remove unused constrcutors and maybe even move exception to higher level.

        public AuthenticationException() {
            super();
        }

        public AuthenticationException(String message, Throwable cause) {
            super(message, cause);
        }

        public AuthenticationException(String message) {
            super(message);
        }

        public AuthenticationException(Throwable cause) {
            super(cause);
        }
    }
}
