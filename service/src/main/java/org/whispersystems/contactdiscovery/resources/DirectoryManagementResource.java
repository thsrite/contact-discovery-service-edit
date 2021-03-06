/*
 * Copyright (C) 2017 Open Whisper Systems
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.whispersystems.contactdiscovery.resources;

import cn.hutool.core.collection.CollUtil;
import com.codahale.metrics.annotation.Timed;
import io.dropwizard.auth.Auth;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.contactdiscovery.auth.SignalService;
import org.whispersystems.contactdiscovery.directory.DirectoryManager;
import org.whispersystems.contactdiscovery.directory.DirectoryUnavailableException;
import org.whispersystems.contactdiscovery.directory.InvalidAddressException;
import org.whispersystems.contactdiscovery.entities.DirectoryReconciliationRequest;
import org.whispersystems.contactdiscovery.entities.DirectoryReconciliationResponse;

import javax.validation.Valid;
import javax.ws.rs.Consumes;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * API endpoint that the Signal service uses to update this micro-services view of
 * registered users.
 *
 * @author Moxie Marlinspike
 */
@Path("/v1/directory")
public class DirectoryManagementResource {

    private final Logger logger = LoggerFactory.getLogger(RemoteAttestationResource.class);

    private final DirectoryManager directoryManager;

    public DirectoryManagementResource(DirectoryManager directoryManager) {
        this.directoryManager = directoryManager;
    }

    @Timed
    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Path("/reconcile")
    public DirectoryReconciliationResponse reconcile(@Auth SignalService signalService,
                                                     @Valid DirectoryReconciliationRequest request)
            throws InvalidAddressException, DirectoryUnavailableException {
        List<DirectoryReconciliationRequest.User> users = request.getUsers();
        logger.debug("users=" + users);
        List<String> collect = CollUtil.isNotEmpty(users) ?
                users.stream().map(DirectoryReconciliationRequest.User::getNumber).collect(Collectors.toList())
                : new ArrayList<>();
        boolean found = directoryManager.reconcile(
                Optional.ofNullable(request.getFromUuid() != null ? request.getFromUuid().toString() : null),
                Optional.ofNullable(request.getToUuid() != null ? request.getToUuid().toString() : null),
                collect);
        if (found) {
            return new DirectoryReconciliationResponse(DirectoryReconciliationResponse.Status.OK);
        } else {
            return new DirectoryReconciliationResponse(DirectoryReconciliationResponse.Status.MISSING);
        }
    }

}
