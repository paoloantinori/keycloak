/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.adapters.osgi;

import java.util.Arrays;
import java.util.Collection;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.servlet.Servlet;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRegistration;

import org.eclipse.jetty.server.handler.ContextHandler;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.servlet.ServletMapping;
import org.jboss.logging.Logger;
import org.ops4j.pax.web.service.WebContainer;
import org.osgi.framework.BundleContext;
import org.osgi.framework.InvalidSyntaxException;
import org.osgi.framework.ServiceReference;
import org.osgi.service.http.HttpContext;
import org.osgi.util.tracker.ServiceTracker;
import org.osgi.util.tracker.ServiceTrackerCustomizer;

/**
 * Service, which allows to remove previously registered servlets in karaf/fuse environment. It assumes that particular servlet was previously
 * registered as service in OSGI container under {@link javax.servlet.Servlet} interface.
 *
 * <p>The point is to register automatically registered builtin servlet endpoints (like "/cxf" for instance) to allow secure them
 * by Keycloak and re-register them again</p>
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class ServletReregistrationService {

    protected static final Logger log = Logger.getLogger(ServletReregistrationService.class);

    private static final List<String> FILTERED_PROPERTIES = Arrays.asList("objectClass", "service.id");

    private BundleContext bundleContext;
    private ServiceReference servletReference;
    private List<ServiceTracker> webContainerTrackers = new CopyOnWriteArrayList<ServiceTracker>();

    public BundleContext getBundleContext() {
        return bundleContext;
    }

    public void setBundleContext(BundleContext bundleContext) {
        this.bundleContext = bundleContext;
    }

    public ServiceReference getServletReference() {
        return servletReference;
    }

    public void setServletReference(ServiceReference servletReference) {
        this.servletReference = servletReference;
    }

    public void start() {
        ServiceReference[] servletContextServiceReferences = new ServiceReference[0];
        try {
            servletContextServiceReferences = bundleContext.getAllServiceReferences("javax.servlet.ServletContext", null);
        } catch (InvalidSyntaxException e) {
            log.error(e);
            return;
        }
        for(ServiceReference serviceContextServiceReference : servletContextServiceReferences){
            WebContainer externalWebContainer = findExternalWebContainer(serviceContextServiceReference);
            if (externalWebContainer == null) {
                continue;
            }
            ServletContextHandler.Context servletContext = (ServletContextHandler.Context) bundleContext.getService(serviceContextServiceReference);
            ServletContextHandler servletContextHandler = (ServletContextHandler) servletContext.getContextHandler();
            //final String contextPath = servletContextHandler.getContextPath();
            ServletHandler servletHandler = servletContextHandler.getServletHandler();
            ServletMapping[] servletMappings = servletHandler.getServletMappings();
            ServletHolder[] servlets = servletContextHandler.getServletHandler().getServlets();
            for(ServletHolder holder : servlets){
                final Servlet servlet;
                final Map<String, String> initParameters;
                String tmpMappingAlias = null;
                try {
                    servlet = holder.getServlet();
                    initParameters = holder.getInitParameters();
                    for(ServletMapping mapping : servletMappings){
                        if(mapping.getServletName().equals(holder.getName())){
                            tmpMappingAlias = mapping.getPathSpecs()[0];
                            log.debug(Arrays.toString(mapping.getPathSpecs()));
                            break;
                        }
                    }

                } catch (ServletException e) {
                    log.error(e);
                    continue;
                }
                // Unregister servlet from external container now
                try {
                    externalWebContainer.unregisterServlet(servlet);
                    log.debugf("Original servlet [%s] with alias [%s] unregistered successfully from external web container [%s].", holder.getName(), tmpMappingAlias, externalWebContainer);
                } catch (RuntimeException e) {
                    log.warnf(e, "Can't unregister servlet [%s] with alias [%s] from [%s]", holder.getName(), tmpMappingAlias, externalWebContainer);
                }

                if(tmpMappingAlias == null)
                    continue;

                final String mappingAlias = tmpMappingAlias;

                ServiceTrackerCustomizer trackerCustomizer = new ServiceTrackerCustomizer() {
                    @Override
                    public Object addingService(ServiceReference webContainerServiceReference) {
                        WebContainer ourWebContainer = (WebContainer) bundleContext.getService(webContainerServiceReference);
                        registerServlet(ourWebContainer, servlet, mappingAlias, initParameters);
                        log.debugf("Servlet with alias [%s] registered to secured web container: [%s]", mappingAlias, ourWebContainer);
                        return ourWebContainer;
                    }

                    @Override
                    public void modifiedService(ServiceReference reference, Object service) {
                    }

                    @Override
                    public void removedService(ServiceReference webContainerServiceReference, Object service) {
                        WebContainer ourWebContainer = (WebContainer) bundleContext.getService(webContainerServiceReference);
                        String alias = mappingAlias;
                        ourWebContainer.unregister(alias);
                        log.debugf("Servlet with alias [%s] unregistered from secured web container", alias);
                    }
                };

                ServiceTracker webContainerTracker = new ServiceTracker(bundleContext, WebContainer.class.getName(), trackerCustomizer);
                webContainerTrackers.add(webContainerTracker);
                webContainerTracker.open();
            }
        }
    }

    public void stop() {
        // Stop tracking our container now and removing reference. This should unregister servlet from our container via trackerCustomizer.removedService (if it's not already unregistered)
//        webContainerTracker.remove(webContainerTracker.getServiceReference());
//
//        // Re-register servlet back to original context
//        WebContainer externalWebContainer = findExternalWebContainer();
//        Servlet servlet = (Servlet) bundleContext.getService(servletReference);
//        registerServlet(externalWebContainer, servlet);
//        log.debug("Servlet with alias " + getAlias() + " registered back to external web container");
    }

    protected void registerServlet(WebContainer webContainer, Servlet servlet, String alias, Map<String, String> initParameters) {
        try {
            Hashtable<String, Object> servletInitParams = new Hashtable<String, Object>();
            Collection<String> propNames = initParameters.keySet();
            for (String propName : propNames) {
                if (!FILTERED_PROPERTIES.contains(propName)) {
                    servletInitParams.put(propName, initParameters.get(propName));
                }
            }

            // Try to register servlet in given web container now
            HttpContext httpContext = webContainer.createDefaultHttpContext();
            webContainer.registerServlet(alias, servlet, servletInitParams, httpContext);
        } catch (Exception e) {
            log.errorf(e, "Can't register servlet with alias [%s] in web container [%s]", alias, webContainer);
        }
    }

    /**
     * Find web container in the bundle, where was servlet originally registered
     *
     * @return web container or null
     */
    protected WebContainer findExternalWebContainer(ServiceReference serviceReference) {
        BundleContext servletBundleContext = serviceReference.getBundle().getBundleContext();
        ServiceReference webContainerReference = servletBundleContext.getServiceReference(WebContainer.class.getName());
        if (webContainerReference == null) {
            log.warn("Not found webContainer reference for bundle " + servletBundleContext);
            return null;
        } else {
            return (WebContainer) servletBundleContext.getService(webContainerReference);
        }
    }

}
