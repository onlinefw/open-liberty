/*******************************************************************************
 * Copyright (c) 2020 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 * 
 * SPDX-License-Identifier: EPL-2.0
 *
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *******************************************************************************/
package io.openliberty.grpc.internal.client;

import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.ClientCall;
import io.grpc.ClientInterceptor;
import io.grpc.ForwardingClientCall.SimpleForwardingClientCall;
import io.grpc.ForwardingClientCallListener.SimpleForwardingClientCallListener;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;

/**
 * An Interceptor used to provide Liberty integrations to outbound gRPC calls.
 * This currently provides generic HTTP header propagation
 */
public class LibertyClientInterceptor implements ClientInterceptor {

	@Override
	public <ReqT, RespT> ClientCall<ReqT, RespT> interceptCall(MethodDescriptor<ReqT, RespT> method,
			CallOptions callOptions, Channel next) {

		return new SimpleForwardingClientCall<ReqT, RespT>(next.newCall(method, callOptions)) {

			@Override
			public void start(Listener<RespT> responseListener, Metadata headers) {
				// grab authority and remove port
				String remoteHost = next.authority();
				if (remoteHost != null) {
					int colonIndex = remoteHost.indexOf(":");
					if (colonIndex > 1) {
						remoteHost = remoteHost.substring(0, colonIndex); 
					}
				}

				// forward any headers that are configured
				LibertyHeaderPropagationSupport.handleHeaderPropagation(remoteHost, method, headers);

				super.start(new SimpleForwardingClientCallListener<RespT>(responseListener) {
				}, headers);
			}
		};
	}
}