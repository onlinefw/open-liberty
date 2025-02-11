/*******************************************************************************
 * Copyright (c) 2015, 2021 IBM Corporation and others.
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
package com.ibm.ws.security.saml.fat.SPInitiated;

import java.util.ArrayList;
import java.util.List;

import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.runner.RunWith;

import com.ibm.websphere.simplicity.log.Log;
import com.ibm.ws.security.fat.common.actions.SecurityTestRepeatAction;
import com.ibm.ws.security.saml.fat.common.BasicEncryptionTests;
import com.ibm.ws.security.saml20.fat.commonTest.SAMLConstants;
import com.ibm.ws.security.saml20.fat.commonTest.SAMLMessageConstants;

import componenttest.custom.junit.runner.FATRunner;
import componenttest.custom.junit.runner.Mode;
import componenttest.custom.junit.runner.Mode.TestMode;
import componenttest.rules.repeater.RepeatTests;
import componenttest.topology.impl.LibertyServerWrapper;

/**
 * In general, these tests perform a simple IdP initiated SAML Web SSO, using httpunit to simulate browser requests.
 * In this scenario, a Web client accesses a static Web page on IdP and obtains a SAML HTTP-POST link to an application
 * installed on a WebSphere SP. When the Web client invokes the SP application, it is redirected to a TFIM IdP which
 * issues a login challenge to the Web client. The Web Client fills in the login form and after a successful login,
 * receives a SAML 2.0 token from the TFIM IdP. The client invokes the SP application by sending the SAML 2.0 token in
 * the HTTP POST request.
 */
@LibertyServerWrapper
@Mode(TestMode.FULL)
@RunWith(FATRunner.class)
public class EncryptionUnsolicitedSPInitiatedTests extends BasicEncryptionTests {

    private static final Class<?> thisClass = EncryptionUnsolicitedSPInitiatedTests.class;

    // only allow test class to run in full mode - tests in "UserFeatureOnlySAMLTests" are used by
    // several classes - some of which do need to run in lite mode...
    @ClassRule
    public static RepeatTests r = RepeatTests.with(new SecurityTestRepeatAction().fullFATOnly());

    @BeforeClass
    public static void setupBeforeTest() throws Exception {

        flowType = SAMLConstants.UNSOLICITED_SP_INITIATED;

        msgUtils.printClassName(thisClass.toString());
        Log.info(thisClass, "setupBeforeTest", "Prep for test");
        // add any additional messages that you want the "start" to wait for
        // we should wait for any providers that this test requires
        List<String> extraMsgs = getDefaultSAMLStartMsgs();

        List<String> extraApps = new ArrayList<String>();
        extraApps.add(SAMLConstants.SAML_CLIENT_APP);

        startSPWithIDPServer("com.ibm.ws.security.saml.sso-2.0_fat.2", "server_enc_aes128_unsolicited.xml", extraMsgs, extraApps, true);

        testSAMLServer.addIgnoredServerException(SAMLMessageConstants.CWWKS5207W_SAML_CONFIG_IGNORE_ATTRIBUTES);

    }

}
