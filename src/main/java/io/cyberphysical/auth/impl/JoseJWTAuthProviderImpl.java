package io.cyberphysical.auth.impl;

import io.cyberphysical.auth.JoseJWTAuth;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import org.apache.commons.lang3.StringUtils;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.JwksVerificationKeyResolver;
import org.jose4j.keys.resolvers.VerificationKeyResolver;
import org.jose4j.lang.JoseException;

/**
 * Created by chuck on 12/29/15.
 */
public class JoseJWTAuthProviderImpl implements JoseJWTAuth {
    private static final JsonObject EMPTY_OBJECT = new JsonObject();
    private final Vertx vertx;
    private final JsonObject config;
    private JwtConsumer jwtConsumer;
    private JwtConsumerBuilder builder;
    private Boolean defaultIgnoreExpiration;
    private Integer defaultAllowedClockSkewInSeconds;
    private String defaultIssuer;
    private String defaultAudience;
    private JsonWebKeySet jsonWebKeySet;


    public JoseJWTAuthProviderImpl(Vertx vertx, JsonObject config) {
        this.vertx = vertx;
        this.config = config;

        final JsonObject jwks = config.getJsonObject("jwks", EMPTY_OBJECT);
        try {
            jsonWebKeySet = new JsonWebKeySet(jwks.toString());
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }


        final VerificationKeyResolver resolver = new JwksVerificationKeyResolver(jsonWebKeySet.getJsonWebKeys());
        Boolean requireSubject = config.getBoolean("requireSubject", true);
        Boolean requireJwtId = config.getBoolean("requireJwtId", true);
        defaultIgnoreExpiration = config.getBoolean("ignoreExpiration", false);
        defaultAllowedClockSkewInSeconds = config.getInteger("allowedClockSkewInSeconds", 30);
        defaultIssuer = config.getString("issuer");
        defaultAudience = config.getString("audience");


        JwtConsumerBuilder defaultBuilder = new JwtConsumerBuilder()
                .setVerificationKeyResolver(resolver);
        if (requireSubject) {
            defaultBuilder = defaultBuilder.setRequireSubject();
        }
        if (requireJwtId) {
            defaultBuilder = defaultBuilder.setRequireJwtId();
        }

        builder = defaultBuilder;

    }

    @Override
    public void authenticate(JsonObject authInfo, Handler<AsyncResult<User>> resultHandler) {
        try {
            final JsonObject options = authInfo.getJsonObject("options", EMPTY_OBJECT);

            if (!options.getBoolean("ignoreExpiration", defaultIgnoreExpiration)) {
                builder = builder
                        .setRequireExpirationTime()
                        .setAllowedClockSkewInSeconds(defaultAllowedClockSkewInSeconds);
            }

            final String audience = options.getString("audience", defaultAudience);
            if (StringUtils.isNotBlank(audience)) {
                builder = builder.setExpectedAudience(audience);
            }

            final String issuer = options.getString("issuer", defaultIssuer);
            if (StringUtils.isNotBlank(issuer)) {
                builder = builder.setExpectedIssuer(issuer);
            }

            jwtConsumer = builder.build();
            final String payload = authInfo.getString("jwt");
            final JwtClaims jwtClaims = jwtConsumer.processToClaims(payload);

            resultHandler.handle(Future.succeededFuture(new JWTUser(jwtClaims)));

        } catch (Exception e) {
            resultHandler.handle(Future.failedFuture(e));
        }
    }

    @Override
    public String generateToken(JwtClaims claims, String keyId, String alg) throws JoseException {
        final RsaJsonWebKey jwk = (RsaJsonWebKey) jsonWebKeySet.findJsonWebKey(keyId, RsaJsonWebKey.KEY_TYPE, null, null);
        final JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(jwk.getPrivateKey());
        jws.setKeyIdHeaderValue(jwk.getKeyId());
        jws.setAlgorithmHeaderValue(alg);
        return jws.getCompactSerialization();
    }
}
