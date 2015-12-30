/*
 * Copyright 2015 Red Hat, Inc.
 *
 *  All rights reserved. This program and the accompanying materials
 *  are made available under the terms of the Eclipse Public License v1.0
 *  and Apache License v2.0 which accompanies this distribution.
 *
 *  The Eclipse Public License is available at
 *  http://www.eclipse.org/legal/epl-v10.html
 *
 *  The Apache License v2.0 is available at
 *  http://www.opensource.org/licenses/apache2.0.php
 *
 *  You may elect to redistribute this code under either of these licenses.
 */

package io.cyberphysical.auth;

import io.cyberphysical.auth.impl.JoseJWTAuthProviderImpl;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthProvider;

import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;


/**
 * Factory interface for creating JWT based {@link io.vertx.ext.auth.AuthProvider} instances.
 *
 * @author Paulo Lopes
 */

public interface JoseJWTAuth extends AuthProvider {

    /**
     * Create a JWT auth provider
     *
     * @param vertx the Vertx instance
     * @param config  the config
     * @return the auth provider
     */
    static JoseJWTAuth create(Vertx vertx, JsonObject config) throws JoseException {
        return new JoseJWTAuthProviderImpl(vertx, config);
    }




    /**
     *
     * @param claims
     * @param keyId
     * @param alg
     * @return
     */
    String generateToken(JwtClaims claims, String keyId, String alg) throws JoseException;


}