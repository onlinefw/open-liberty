/*******************************************************************************
 * Copyright (c) 2023 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Contributors:
 * IBM Corporation - initial API and implementation
 *******************************************************************************/
package com.ibm.ws.security.openidconnect.client.fat.IBM;

import java.util.ArrayList;
import java.util.List;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.ibm.ws.security.fat.common.jwt.JWTTokenBuilder;
import com.ibm.ws.security.fat.common.jwt.PayloadConstants;
import com.ibm.ws.security.fat.common.jwt.utils.JwtTokenBuilderUtils;
import com.ibm.ws.security.oauth_oidc.fat.commonTest.CommonTest;
import com.ibm.ws.security.oauth_oidc.fat.commonTest.Constants;
import com.ibm.ws.security.oauth_oidc.fat.commonTest.EndpointSettings.endpointSettings;
import com.ibm.ws.security.oauth_oidc.fat.commonTest.MessageConstants;
import com.ibm.ws.security.oauth_oidc.fat.commonTest.TestSettings;
import com.ibm.ws.security.oauth_oidc.fat.commonTest.ValidationData.validationData;
import com.meterware.httpunit.WebConversation;

import componenttest.custom.junit.runner.FATRunner;
import componenttest.custom.junit.runner.Mode;
import componenttest.custom.junit.runner.Mode.TestMode;

/**
 * This is the test class that will run tests to verify <Fill in description here>
 *
 **/

@Mode(TestMode.FULL)
@RunWith(FATRunner.class)
public class OidXXXTests extends CommonTest {

    public static Class<?> thisClass = OidXXXTests.class;

    public static final JwtTokenBuilderUtils tokenBuilderHelpers = new JwtTokenBuilderUtils();

    @SuppressWarnings("serial")
    @BeforeClass
    public static void setUp() throws Exception {

        List<String> apps = new ArrayList<String>() {
            {
                add(Constants.OPENID_APP);
            }
        };

        // apps are taking too long to start up for the normal app check, but, we need to be sure that they're ready before we try to use them.
        List<String> opExtraMsgs = new ArrayList<String>() {
            {
                add("CWWKZ0001I.*" + Constants.TOKEN_ENDPOINT_SERVLET);
            }
        };

        testSettings = new TestSettings();

        // Set config parameters for Access token with X509 Certificate in OP config files
        String tokenType = Constants.ACCESS_TOKEN_KEY;
        String certType = Constants.X509_CERT;

        // Start the OIDC OP server
        testOPServer = commonSetUp("com.ibm.ws.security.openidconnect.client-1.0_fat.4.opWithStub", "op_server_orig.xml", Constants.OIDC_OP, Constants.NO_EXTRA_APPS,
                Constants.DO_NOT_USE_DERBY, opExtraMsgs, Constants.OPENID_APP, Constants.IBMOIDC_TYPE, true, true, tokenType, certType);

        //Start the OIDC RP server and setup default values
        testRPServer = commonSetUp("com.ibm.ws.security.openidconnect.client-1.0_fat.4.rp", "rp_server_orig.xml", Constants.OIDC_RP, apps, Constants.DO_NOT_USE_DERBY,
                Constants.NO_EXTRA_MSGS, Constants.OPENID_APP, Constants.IBMOIDC_TYPE, true, true, tokenType, certType);

        testSettings.setFlowType(Constants.RP_FLOW);
        testSettings.setTokenEndpt(testSettings.getTokenEndpt()
                .replace("oidc/endpoint/OidcConfigSample/token", "TokenEndpointServlet")
                .replace("oidc/providers/OidcConfigSample/token", "TokenEndpointServlet") + "/saveToken");

    }

    public JWTTokenBuilder createBuilderWithDefaultClaims() throws Exception {

        JWTTokenBuilder builder = new JWTTokenBuilder();
        builder.setIssuer(testOPServer.getHttpString() + "/TokenEndpointServlet");
        builder.setIssuedAtToNow();
        builder.setExpirationTimeMinutesIntheFuture(5);
        builder.setScope("openid profile");
        builder.setSubject("testuser");
        builder.setRealmName("BasicRealm");
        builder.setTokenType("Bearer");
        builder.setAudience("client01");
        builder.setClaim(PayloadConstants.SESSION_ID, JwtTokenBuilderUtils.randomSessionId());
        builder.setAlorithmHeaderValue(Constants.SIGALG_RS256);
        builder.setRSAKey(testOPServer.getServer().getServerRoot() + "/RS256private-key.pem");
        return builder;
    }

    /******************************* tests *******************************/
    /************** jwt builder/rp using the same algorithm **************/
    /**
     * Test shows that the RP can consume a JWT token with <some extra value, ...>
     *
     * @throws Exception
     */
    @Test
    public void OidXXXTests_RPCanConsume_xxx() throws Exception {

        String appName = "sampleBuilder";

        WebConversation wc = new WebConversation();
        TestSettings updatedTestSettings = testSettings.copyTestSettings();
        updatedTestSettings.setScope("openid profile");
        updatedTestSettings.setTestURL(testSettings.getTestURL().replace("SimpleServlet", "simple/" + appName));

        List<validationData> expectations = vData.addSuccessStatusCodes(null);
        expectations = validationTools.addIdTokenStringValidation(vData, expectations, Constants.LOGIN_USER, Constants.RESPONSE_FULL, Constants.IDToken_STR);
        // The next 2 expectations allow the tests to get error messages when calling userinfo (without
        // these checks, the test framework will find unexpected messages and mark the test as an error)
        expectations = validationTools.addMessageExpectation(testOPServer, expectations, Constants.LOGIN_USER, Constants.MESSAGES_LOG, Constants.STRING_CONTAINS, "Did not find a message indicating that the request to the userinfo endpoint was not authorized", MessageConstants.CWWKS1617E_USERINFO_REQUEST_BAD_TOKEN);
        expectations = validationTools.addMessageExpectation(testRPServer, expectations, Constants.LOGIN_USER, Constants.MESSAGES_LOG, Constants.STRING_CONTAINS, "Did not find a message indicating that the request to the userinfo endpoint was not authorized", MessageConstants.CWWKS1748E_USERINFO_REQUEST_NOT_AUTHORIZED);

        // add or update claims (To remove claims you might need to replicate what createBuilderWithDefaultClaims does and just omit the setting of the claim)
        JWTTokenBuilder builder = createBuilderWithDefaultClaims();
        builder.setClaim("auth_time", builder.getRawClaims().getClaimValue(PayloadConstants.ISSUED_AT));
        expectations = vData.addExpectation(expectations, Constants.LOGIN_USER, Constants.RESPONSE_FULL, Constants.STRING_CONTAINS, "Did not see the auth_time printed in the app output", null, "\"auth_time\":" + builder.getRawClaims().getClaimValue("auth_time"));
        builder.setClaim(PayloadConstants.USER_PRINCIPAL_NAME, "myEmail@ibm.com");
        expectations = vData.addExpectation(expectations, Constants.LOGIN_USER, Constants.RESPONSE_FULL, Constants.STRING_CONTAINS, "Did not see the " + PayloadConstants.USER_PRINCIPAL_NAME + " printed in the app output", null, "\"" + PayloadConstants.USER_PRINCIPAL_NAME + "\":\"" + builder.getRawClaims().getClaimValue(PayloadConstants.USER_PRINCIPAL_NAME) + "\"");
        builder.setClaim("unique_name", builder.getRawClaims().getClaimValue(PayloadConstants.SESSION_ID));
        expectations = vData.addExpectation(expectations, Constants.LOGIN_USER, Constants.RESPONSE_FULL, Constants.STRING_CONTAINS, "Did not see the unique_name printed in the app output", null, "\"unique_name\":\"" + builder.getRawClaims().getClaimValue("unique_name") + "\"");

        //        builder.setClaim("token_src", "testcase builder");
        //        builder.setClaim(Constants.PAYLOAD_AT_HASH, "dummy_hash_value");
        //        builder.setClaim(Constants.IDTOK_UNIQ_SEC_NAME_KEY, "testuser");
        //        builder.setClaim("someExraClaim", "someExtraClaimValue");
        // calling build to create a JWT token (as a string)
        String jwtToken = builder.build();

        // the built token will be passed to the test app via the overrideToken parm - it will be saved to be later returned during the auth process.
        List<endpointSettings> parms = eSettings.addEndpointSettingsIfNotNull(null, "overrideToken", jwtToken);
        genericInvokeEndpointWithHttpUrlConn(_testName, null, updatedTestSettings.getTokenEndpt(), Constants.PUTMETHOD, "misc", parms, null, expectations);

        // we created and saved a jwt for our test tooling token endpoint to return to the RP - let's invoke
        // the protected resource.  The RP will get the auth token, but, instead of getting a jwt from the OP, it will use a
        // token endpoint pointing to the test tooling app that will return the jwt previously obtained using a builder
        genericRP(_testName, wc, updatedTestSettings, Constants.GOOD_OIDC_LOGIN_ACTIONS_SKIP_CONSENT, expectations);

    }

}
