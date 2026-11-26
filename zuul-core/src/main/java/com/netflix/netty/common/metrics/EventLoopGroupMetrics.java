/*
 * Copyright 2018 Netflix, Inc.
 *
 *      Licensed under the Apache License, Version 2.0 (the "License");
 *      you may not use this file except in compliance with the License.
 *      You may obtain a copy of the License at
 *
 *          http://www.apache.org/licenses/LICENSE-2.0
 *
 *      Unless required by applicable law or agreed to in writing, software
 *      distributed under the License is distributed on an "AS IS" BASIS,
 *      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *      See the License for the specific language governing permissions and
 *      limitations under the License.
 */

package com.netflix.netty.common.metrics;

import com.netflix.spectator.api.Registry;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * User: michaels@netflix.com
 * Date: 2/7/17
 * Time: 3:17 PM
 */
@Singleton
public class EventLoopGroupMetrics {
    private final Registry registry;
    private final Map<Thread, EventLoopMetrics> byEventLoop = new ConcurrentHashMap<>();

    @Inject
    public EventLoopGroupMetrics(Registry registry) {
        this.registry = registry;
    }

    public Map<Thread, Integer> connectionsPerEventLoop() {
        Map<Thread, Integer> map = new HashMap<>(byEventLoop.size());
        for (Map.Entry<Thread, EventLoopMetrics> entry : byEventLoop.entrySet()) {
            map.put(entry.getKey(), entry.getValue().currentConnectionsCount());
        }
        return map;
    }

    public Map<Thread, Integer> httpRequestsPerEventLoop() {
        Map<Thread, Integer> map = new HashMap<>(byEventLoop.size());
        for (Map.Entry<Thread, EventLoopMetrics> entry : byEventLoop.entrySet()) {
            map.put(entry.getKey(), entry.getValue().currentHttpRequestsCount());
        }
        return map;
    }

    public EventLoopMetrics getForCurrentEventLoop() {
        Thread currentThread = Thread.currentThread();
        return byEventLoop.computeIfAbsent(
                currentThread, thread -> new EventLoopMetrics(registry, nameForCurrentEventLoop(thread.getName())));
    }

    private static String nameForCurrentEventLoop(String threadName) {
        // We're relying on the knowledge that we name the eventloop threads consistently.
        String parts[] = threadName.split("-ClientToZuulWorker-", -1);
        if (parts.length == 2) {
            return parts[1];
        }
        return threadName;
    }

    interface EventLoopInfo {
        int currentConnectionsCount();

        int currentHttpRequestsCount();
    }
}
