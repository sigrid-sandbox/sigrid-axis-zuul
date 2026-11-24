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

package com.netflix.zuul.netty.server;

import java.util.concurrent.Callable;
import java.util.function.BiConsumer;

/**
 * Utility used for binding context variables or thread variables, depending on requirements.
 *
 * Author: Arthur Gonigberg
 * Date: November 29, 2017
 */
@Deprecated
public class MethodBinding<T> extends com.netflix.zuul.netty.MethodBinding<T> {

    public static final MethodBinding<?> NO_OP_BINDING = new MethodBinding<>((r, t) -> {}, () -> null);

    public MethodBinding(BiConsumer<Runnable, T> boundMethod, Callable<T> bindingContextExtractor) {
        super(boundMethod, bindingContextExtractor);
    }
}
