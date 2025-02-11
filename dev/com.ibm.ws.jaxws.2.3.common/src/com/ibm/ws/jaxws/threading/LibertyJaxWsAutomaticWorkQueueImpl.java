/*******************************************************************************
 * Copyright (c) 2019,2020 IBM Corporation and others.
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
package com.ibm.ws.jaxws.threading;

import java.security.AccessController;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.apache.cxf.workqueue.AutomaticWorkQueue;

import com.ibm.ws.util.ThreadContextAccessor;
import com.ibm.wsspi.threading.WSExecutorService;

public class LibertyJaxWsAutomaticWorkQueueImpl implements AutomaticWorkQueue {

    private static final ThreadContextAccessor THREAD_CONTEXT_ACCESSOR =
                    AccessController.doPrivileged(ThreadContextAccessor.getPrivilegedAction());

    /**
     * Borrowed from jaxrs-2.x to udpate our LibertyThreadPoolAdapter to match changes need for CXF Updates
     * LibertyJaxWsWorker helps to switch the Thread Context Classloader of InvocationCallback & CompletionCallback to application context classloader which can access the jaxws-2.3
     * spec API such as Client API
     */
    public class LibertyJaxWsWorker implements Runnable {

        private final Runnable work;
        private final ClassLoader appContextClassLoader;

        public LibertyJaxWsWorker(Runnable work) {
            this.work = work;
            //get the application context classloader from main thread
            this.appContextClassLoader = THREAD_CONTEXT_ACCESSOR.getContextClassLoader(Thread.currentThread());
        }

        @Override
        public void run() {

            //switch thread context classloader of async thread to application context classloader
            ClassLoader oClsLoader = THREAD_CONTEXT_ACCESSOR.getContextClassLoader(Thread.currentThread());
            
            try {
                THREAD_CONTEXT_ACCESSOR.setContextClassLoader(Thread.currentThread(), appContextClassLoader);
                work.run();
            } finally {
                //after callback done, switch back the original classloader
                THREAD_CONTEXT_ACCESSOR.setContextClassLoader(Thread.currentThread(), oClsLoader);
            }
        }
    }
    
    private final ScheduledExecutorService scheduleExecutor;

    private final WSExecutorService wsExecutorService;

    final private String name;

    public LibertyJaxWsAutomaticWorkQueueImpl(ScheduledExecutorService scheduleExecutor, WSExecutorService executor) {
        this.name = "default";
        this.wsExecutorService = executor;
        this.scheduleExecutor = scheduleExecutor;
    }

    @Override
    public void execute(Runnable work, long timeout) {
        wsExecutorService.executeGlobal(work);
    }

    @Override
    public void schedule(Runnable work, long delay) {
        this.scheduleExecutor.schedule(work, delay, TimeUnit.MILLISECONDS);
    }

    @Override
    public void execute(Runnable work) {
        wsExecutorService.executeGlobal(work);
    }

    @Override
    public String getName() {
        return this.name;
    }

    @Override
    public boolean isShutdown() {
        return false;
    }

    @Override
    public void shutdown(boolean processRemainingWorkItems) {
        // do nothing so far as LibertyJaxwsAutomaticWorkQueueImpl can not be shutdown
    }

}
