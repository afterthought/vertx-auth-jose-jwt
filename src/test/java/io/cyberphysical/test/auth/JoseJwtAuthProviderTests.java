package io.cyberphysical.test.auth;

import io.cyberphysical.auth.JoseJWTAuth;
import io.netty.util.internal.ConcurrentSet;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import io.vertx.ext.web.handler.JWTAuthHandler;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jwk.Use;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Created by chuck on 12/30/15.
 */
@RunWith(VertxUnitRunner.class)
public class JoseJwtAuthProviderTests {

    public static final String KEY_ID = "k1";
    private RsaJsonWebKey rsaJsonWebKey;

    @Before
    public void setup(TestContext context) throws JoseException {
        rsaJsonWebKey = RsaJwkGenerator.generateJwk(2048);
        rsaJsonWebKey.setKeyId(KEY_ID);
    }
    @Test
    public void testCanVerifyJwt(TestContext context) throws JoseException {

        final String keyJson = rsaJsonWebKey.toJson(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE);
        final JsonObject config = new JsonObject()
                .put("issuer", "mytest")
                .put("audience", "developers")
                .put("jwks", buildKeySetFromKey(keyJson));
        final JoseJWTAuth joseJWTAuth = JoseJWTAuth.create(Vertx.vertx(), config);

        final JwtClaims claims = new JwtClaims();
        claims.setJwtId("myId");
        claims.setIssuer("mytest");
        claims.setAudience("developers");
        claims.setSubject("abc");
        claims.setExpirationTimeMinutesInTheFuture(5);
        final String token = joseJWTAuth.generateToken(claims, KEY_ID, AlgorithmIdentifiers.RSA_USING_SHA256);

        final JsonObject authInfo = new JsonObject().put("jwt", token);
        joseJWTAuth.authenticate(authInfo, context.asyncAssertSuccess(user -> {
            context.assertEquals("myId", user.principal().getString("jti"));
        }));
    }

    @Test
    public void testCanVerifyJwtAuthorities(TestContext context) throws JoseException {

        final String keyJson = rsaJsonWebKey.toJson(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE);
        final JsonObject config = new JsonObject()
                .put("issuer", "mytest")
                .put("audience", "developers")
                .put("jwks", buildKeySetFromKey(keyJson));
        final JoseJWTAuth joseJWTAuth = JoseJWTAuth.create(Vertx.vertx(), config);

        final JwtClaims claims = new JwtClaims();
        claims.setJwtId("myId");
        claims.setIssuer("mytest");
        claims.setAudience("developers");
        claims.setSubject("abc");
        claims.setStringListClaim("scopes", "role1", "role2");
        claims.setExpirationTimeMinutesInTheFuture(5);
        final String token = joseJWTAuth.generateToken(claims, KEY_ID, AlgorithmIdentifiers.RSA_USING_SHA256);

        final JsonObject authInfo = new JsonObject().put("jwt", token);
        joseJWTAuth.authenticate(authInfo, context.asyncAssertSuccess(user -> {
            context.assertEquals("myId", user.principal().getString("jti"));
            user.isAuthorised("role1", context.asyncAssertSuccess(context::assertTrue));
            user.isAuthorised("role2", context.asyncAssertSuccess(context::assertTrue));
            user.isAuthorised("bogusRole", context.asyncAssertSuccess(context::assertFalse));
        }));


    }

    /**
     * The JSON in config is expected to be in the format:
     *
     * {
     *     jwks: {
     *         keys: [{key}]
     *     }
     * }
     *
     * https://tools.ietf.org/html/draft-ietf-jose-json-web-key-40#section-5
     * @param keyJson
     * @return
     */
    private JsonObject buildKeySetFromKey(String keyJson) {
        return new JsonObject().put("keys", new JsonArray().add(new JsonObject(keyJson)));
    }
}
