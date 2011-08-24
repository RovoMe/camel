/**
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.camel.component.jetty;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * The camel filter wrapper that processes only initially dispatched requests.
 * Re-dispatched requests are ignored.
 */

public class CamelFilterWrapper implements Filter {
    
    private Filter wrapped;

    public CamelFilterWrapper(Filter wrapped) {
        this.wrapped = wrapped;
    }
    
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (request.getAttribute(CamelContinuationServlet.EXCHANGE_ATTRIBUTE_NAME) == null) {
            wrapped.doFilter(request, response, chain);
        } else {
            chain.doFilter(request, response);
        }
    }

    public void destroy() {
        wrapped.destroy();
    }

    public void init(FilterConfig config) throws ServletException {
        wrapped.init(config);
    }

}
