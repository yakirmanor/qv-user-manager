﻿using System;
using System.Collections.Generic;
using System.Linq;
using qv_user_manager.QMSBackendService;

namespace qv_user_manager
{
    class DocumentMetadataService
    {
        /// <summary>
        /// Add DMS users
        /// </summary>
        /// <param name="documents"></param>
        /// <param name="users"></param>
        public static void Add(ICollection<string> documents, ICollection<string> users)
        {
            try
            {
                // Initiate backend client
                var backendClient = new QMSBackendClient();

                // Get a time limited service key
                ServiceKeyClientMessageInspector.ServiceKey = backendClient.GetTimeLimitedServiceKey();

                // Get available QlikView Servers
                var serviceList = backendClient.GetServices(ServiceTypes.QlikViewServer);

                // Loop through available servers
                foreach (var server in serviceList)
                {
                    // Get documents on each server
                    var userDocuments = backendClient.GetUserDocuments(server.ID);

                    // Loop through available documents
                    foreach (var docNode in userDocuments)
                    {
                        // Continue if no matching documents
                        if (documents.Count != 0 && !documents.Contains(docNode.Name.ToLower())) continue;

                        // Get authorization metadata
                        var metaData = backendClient.GetDocumentMetaData(docNode, DocumentMetaDataScope.Authorization);

                        // Filter users already in DMS from the supplied list of users to avoid duplicates
                        var uniqueUsers = users.Except(metaData.Authorization.Access.Select(user => user.UserName).ToList());

                        // Get number of users on each document
                        var numberOfUsers = metaData.Authorization.Access.Count;

                        // Add new users
                        foreach (var user in uniqueUsers.Select(u => new DocumentAccessEntry
                        {
                            UserName = u,
                            AccessMode = DocumentAccessEntryMode.Always,
                            DayOfWeekConstraints = new List<DayOfWeek>()
                        }))
                        {
                            metaData.Authorization.Access.Add(user);
                        }

                        // Save changes
                        backendClient.SaveDocumentMetaData(metaData);

                        // Get number of users AFTER modifications
                        var addedUsers = metaData.Authorization.Access.Count - numberOfUsers;

                        if (addedUsers <= 0)
                            Console.WriteLine(String.Format("Nothing to add to '{0}' on {1}", docNode.Name, server.Name));
                        else
                            Console.WriteLine(String.Format("Added {0} users to '{1}' on {2}", addedUsers, docNode.Name, server.Name));
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }

        /// <summary>
        /// List DMS users
        /// </summary>
        /// <param name="documents"></param>
        public static void List(ICollection<string> documents)
        {
            try
            {
                // Initiate backend client
                var backendClient = new QMSBackendClient();

                // Get a time limited service key
                ServiceKeyClientMessageInspector.ServiceKey = backendClient.GetTimeLimitedServiceKey();

                // Get available QlikView Servers
                var serviceList = backendClient.GetServices(ServiceTypes.QlikViewServer);

                Console.WriteLine("UserName;Document;Server");

                // Loop through available servers
                foreach (var server in serviceList)
                {
                    // Get documents on each server
                    var userDocuments = backendClient.GetUserDocuments(server.ID);

                    // Loop through available documents
                    foreach (var docNode in userDocuments)
                    {
                        if (documents.Count != 0 && !documents.Contains(docNode.Name.ToLower())) continue;

                        // Get authorization meta data
                        var metaData = backendClient.GetDocumentMetaData(docNode, DocumentMetaDataScope.Authorization);

                        foreach (var user in metaData.Authorization.Access)
                            Console.WriteLine(String.Format("{0};{1};{2}", user.UserName, docNode.Name, server.Name));
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }

        }

        /// <summary>
        /// Remove DMS users
        /// </summary>
        /// <param name="documents"></param>
        /// <param name="users"></param>
        public static void Remove(ICollection<string> documents, List<string> users)
        {
            try
            {
                // Initiate backend client
                var backendClient = new QMSBackendClient();

                // Get a time limited service key
                ServiceKeyClientMessageInspector.ServiceKey = backendClient.GetTimeLimitedServiceKey();

                // Get available QlikView Servers
                var serviceList = backendClient.GetServices(ServiceTypes.QlikViewServer);

                // Convert all usernames to lowercase
                users = users.ConvertAll(d => d.ToLower());

                // Loop through available servers
                foreach (var server in serviceList)
                {
                    // Get documents on each server
                    var userDocuments = backendClient.GetUserDocuments(server.ID);

                    // Loop through available documents
                    foreach (var docNode in userDocuments)
                    {
                        // Continue if no matching documents
                        if (documents.Count != 0 && !documents.Contains(docNode.Name.ToLower())) continue;

                        // Get authorization metadata
                        var metaData = backendClient.GetDocumentMetaData(docNode, DocumentMetaDataScope.Authorization);

                        // Get number of users BEFORE modifications
                        var numberOfUsers = metaData.Authorization.Access.Count;

                        if (users.Count == 0)
                            // Remove all users if no users were specified
                            metaData.Authorization.Access.RemoveRange(0, numberOfUsers);
                        else
                        {
                            // Remove matching users
                            foreach (var u in metaData.Authorization.Access.ToList().Where(u => users.Contains(u.UserName.ToLower())))
                                metaData.Authorization.Access.Remove(u);
                        }

                        // Save changes
                        backendClient.SaveDocumentMetaData(metaData);

                        // Get number of users AFTER modifications
                        var removedUsers = numberOfUsers - metaData.Authorization.Access.Count;

                        if (removedUsers <= 0)
                            Console.WriteLine(String.Format("Nothing to remove from '{0}' on {1}", docNode.Name, server.Name));
                        else
                            Console.WriteLine(String.Format("Removed {0} users from '{1}' on {2}", removedUsers, docNode.Name, server.Name));
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }

        }
    }
}
