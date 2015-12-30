package io.cyberphysical.auth.impl;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AbstractUser;
import io.vertx.ext.auth.AuthProvider;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;

import java.util.List;

/**
 * Created by chuck on 12/29/15.
 */
public class JWTUser extends AbstractUser {

    private final JwtClaims jwtClaims;

    public JWTUser(JwtClaims jwtClaims) {

        this.jwtClaims = jwtClaims;
    }

    @Override
    protected void doIsPermitted(String permission, Handler<AsyncResult<Boolean>> resultHandler) {
        final List<String> scopes;
        try {
            scopes = jwtClaims.getStringListClaimValue("scopes");
            resultHandler.handle(Future.succeededFuture(scopes.contains(permission)));
        } catch (MalformedClaimException e) {
            resultHandler.handle(Future.failedFuture(e));
        }
    }

    @Override
    public JsonObject principal() {
        return new JsonObject(jwtClaims.getClaimsMap());
    }

    @Override
    public void setAuthProvider(AuthProvider authProvider) {
        // NOOP - JWT tokens are self contained :)
    }
}
