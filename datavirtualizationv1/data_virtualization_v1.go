/**
 * (C) Copyright IBM Corp. 2021.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * IBM OpenAPI SDK Code Generator Version: 3.19.0-be3b4618-20201113-200858
 */
 

// Package datavirtualizationv1 : Operations and models for the DataVirtualizationV1 service
package datavirtualizationv1

import (
	"context"
	"encoding/json"
	"fmt"
	common "github.com/IBM/data-virtualization/common"
	"github.com/IBM/go-sdk-core/v4/core"
	"net/http"
	"reflect"
	"time"
)

// DataVirtualizationV1 : The Data Virtualization REST API connects to your service, so you can manage your virtual
// data, data sources, and user roles.
//
// Version: 1.6.0
type DataVirtualizationV1 struct {
	Service *core.BaseService
}

// DefaultServiceURL is the default URL to make service requests to.
const DefaultServiceURL = "https://data-virtualization.cloud.ibm.com"

// DefaultServiceName is the default key used to find external configuration information.
const DefaultServiceName = "data_virtualization"

// DataVirtualizationV1Options : Service options
type DataVirtualizationV1Options struct {
	ServiceName   string
	URL           string
	Authenticator core.Authenticator
}

// NewDataVirtualizationV1 : constructs an instance of DataVirtualizationV1 with passed in options.
func NewDataVirtualizationV1(options *DataVirtualizationV1Options) (service *DataVirtualizationV1, err error) {
	if options.ServiceName == "" {
		options.ServiceName = DefaultServiceName
	}

	serviceOptions := &core.ServiceOptions{
		URL:           DefaultServiceURL,
		Authenticator: options.Authenticator,
	}

	if serviceOptions.Authenticator == nil {
		serviceOptions.Authenticator, err = core.GetAuthenticatorFromEnvironment(options.ServiceName)
		if err != nil {
			return
		}
	}

	baseService, err := core.NewBaseService(serviceOptions)
	if err != nil {
		return
	}

	err = baseService.ConfigureService(options.ServiceName)
	if err != nil {
		return
	}

	if options.URL != "" {
		err = baseService.SetServiceURL(options.URL)
		if err != nil {
			return
		}
	}

	service = &DataVirtualizationV1{
		Service: baseService,
	}

	return
}

// SetServiceURL sets the service URL
func (dataVirtualization *DataVirtualizationV1) SetServiceURL(url string) error {
	return dataVirtualization.Service.SetServiceURL(url)
}

// GetServiceURL returns the service URL
func (dataVirtualization *DataVirtualizationV1) GetServiceURL() string {
	return dataVirtualization.Service.GetServiceURL()
}

// SetDefaultHeaders sets HTTP headers to be sent in every request
func (dataVirtualization *DataVirtualizationV1) SetDefaultHeaders(headers http.Header) {
	dataVirtualization.Service.SetDefaultHeaders(headers)
}

// SetEnableGzipCompression sets the service's EnableGzipCompression field
func (dataVirtualization *DataVirtualizationV1) SetEnableGzipCompression(enableGzip bool) {
	dataVirtualization.Service.SetEnableGzipCompression(enableGzip)
}

// GetEnableGzipCompression returns the service's EnableGzipCompression field
func (dataVirtualization *DataVirtualizationV1) GetEnableGzipCompression() bool {
	return dataVirtualization.Service.GetEnableGzipCompression()
}

// EnableRetries enables automatic retries for requests invoked for this service instance.
// If either parameter is specified as 0, then a default value is used instead.
func (dataVirtualization *DataVirtualizationV1) EnableRetries(maxRetries int, maxRetryInterval time.Duration) {
	dataVirtualization.Service.EnableRetries(maxRetries, maxRetryInterval)
}

// DisableRetries disables automatic retries for requests invoked for this service instance.
func (dataVirtualization *DataVirtualizationV1) DisableRetries() {
	dataVirtualization.Service.DisableRetries()
}

// AddDatasourceConnection : Add data source connection
// Adds a data source connection to the Data Virtualization service.
func (dataVirtualization *DataVirtualizationV1) AddDatasourceConnection(addDatasourceConnectionOptions *AddDatasourceConnectionOptions) (response *core.DetailedResponse, err error) {
	return dataVirtualization.AddDatasourceConnectionWithContext(context.Background(), addDatasourceConnectionOptions)
}

// AddDatasourceConnectionWithContext is an alternate form of the AddDatasourceConnection method which supports a Context parameter
func (dataVirtualization *DataVirtualizationV1) AddDatasourceConnectionWithContext(ctx context.Context, addDatasourceConnectionOptions *AddDatasourceConnectionOptions) (response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(addDatasourceConnectionOptions, "addDatasourceConnectionOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(addDatasourceConnectionOptions, "addDatasourceConnectionOptions")
	if err != nil {
		return
	}

	builder := core.NewRequestBuilder(core.POST)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = dataVirtualization.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(dataVirtualization.Service.Options.URL, `/v2/datasource_connections`, nil)
	if err != nil {
		return
	}

	for headerName, headerValue := range addDatasourceConnectionOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("data_virtualization", "V1", "AddDatasourceConnection")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}
	builder.AddHeader("Content-Type", "application/json")

	body := make(map[string]interface{})
	if addDatasourceConnectionOptions.DatasourceType != nil {
		body["datasource_type"] = addDatasourceConnectionOptions.DatasourceType
	}
	if addDatasourceConnectionOptions.Name != nil {
		body["name"] = addDatasourceConnectionOptions.Name
	}
	if addDatasourceConnectionOptions.OriginCountry != nil {
		body["origin_country"] = addDatasourceConnectionOptions.OriginCountry
	}
	if addDatasourceConnectionOptions.Properties != nil {
		body["properties"] = addDatasourceConnectionOptions.Properties
	}
	if addDatasourceConnectionOptions.AssetCategory != nil {
		body["asset_category"] = addDatasourceConnectionOptions.AssetCategory
	}
	if addDatasourceConnectionOptions.RemoteNodes != nil {
		body["remote_nodes"] = addDatasourceConnectionOptions.RemoteNodes
	}
	_, err = builder.SetBodyContentJSON(body)
	if err != nil {
		return
	}

	request, err := builder.Build()
	if err != nil {
		return
	}

	response, err = dataVirtualization.Service.Request(request, nil)

	return
}

// DeleteDatasourceConnection : Delete data source connection
// Deletes a data source connection from the Data Virtualization service.
func (dataVirtualization *DataVirtualizationV1) DeleteDatasourceConnection(deleteDatasourceConnectionOptions *DeleteDatasourceConnectionOptions) (response *core.DetailedResponse, err error) {
	return dataVirtualization.DeleteDatasourceConnectionWithContext(context.Background(), deleteDatasourceConnectionOptions)
}

// DeleteDatasourceConnectionWithContext is an alternate form of the DeleteDatasourceConnection method which supports a Context parameter
func (dataVirtualization *DataVirtualizationV1) DeleteDatasourceConnectionWithContext(ctx context.Context, deleteDatasourceConnectionOptions *DeleteDatasourceConnectionOptions) (response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(deleteDatasourceConnectionOptions, "deleteDatasourceConnectionOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(deleteDatasourceConnectionOptions, "deleteDatasourceConnectionOptions")
	if err != nil {
		return
	}

	builder := core.NewRequestBuilder(core.DELETE)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = dataVirtualization.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(dataVirtualization.Service.Options.URL, `/v2/datasource_connections`, nil)
	if err != nil {
		return
	}

	for headerName, headerValue := range deleteDatasourceConnectionOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("data_virtualization", "V1", "DeleteDatasourceConnection")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}
	builder.AddHeader("Content-Type", "application/json")

	body := make(map[string]interface{})
	if deleteDatasourceConnectionOptions.Cid != nil {
		body["cid"] = deleteDatasourceConnectionOptions.Cid
	}
	if deleteDatasourceConnectionOptions.ConnectionID != nil {
		body["connection_id"] = deleteDatasourceConnectionOptions.ConnectionID
	}
	_, err = builder.SetBodyContentJSON(body)
	if err != nil {
		return
	}

	request, err := builder.Build()
	if err != nil {
		return
	}

	response, err = dataVirtualization.Service.Request(request, nil)

	return
}

// GetDatasourceNodes : Get data source nodes
// Gets all data source nodes that are connected to the service.
func (dataVirtualization *DataVirtualizationV1) GetDatasourceNodes(getDatasourceNodesOptions *GetDatasourceNodesOptions) (result *DatasourceNodesResponseV2, response *core.DetailedResponse, err error) {
	return dataVirtualization.GetDatasourceNodesWithContext(context.Background(), getDatasourceNodesOptions)
}

// GetDatasourceNodesWithContext is an alternate form of the GetDatasourceNodes method which supports a Context parameter
func (dataVirtualization *DataVirtualizationV1) GetDatasourceNodesWithContext(ctx context.Context, getDatasourceNodesOptions *GetDatasourceNodesOptions) (result *DatasourceNodesResponseV2, response *core.DetailedResponse, err error) {
	err = core.ValidateStruct(getDatasourceNodesOptions, "getDatasourceNodesOptions")
	if err != nil {
		return
	}

	builder := core.NewRequestBuilder(core.GET)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = dataVirtualization.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(dataVirtualization.Service.Options.URL, `/v2/datasource_nodes`, nil)
	if err != nil {
		return
	}

	for headerName, headerValue := range getDatasourceNodesOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("data_virtualization", "V1", "GetDatasourceNodes")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}
	builder.AddHeader("Accept", "application/json")

	request, err := builder.Build()
	if err != nil {
		return
	}

	var rawResponse map[string]json.RawMessage
	response, err = dataVirtualization.Service.Request(request, &rawResponse)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(rawResponse, "", &result, UnmarshalDatasourceNodesResponseV2)
	if err != nil {
		return
	}
	response.Result = result

	return
}

// GrantUserToObject : Grant user access
// Grants a user access to a specific virtualized table.
func (dataVirtualization *DataVirtualizationV1) GrantUserToObject(grantUserToObjectOptions *GrantUserToObjectOptions) (response *core.DetailedResponse, err error) {
	return dataVirtualization.GrantUserToObjectWithContext(context.Background(), grantUserToObjectOptions)
}

// GrantUserToObjectWithContext is an alternate form of the GrantUserToObject method which supports a Context parameter
func (dataVirtualization *DataVirtualizationV1) GrantUserToObjectWithContext(ctx context.Context, grantUserToObjectOptions *GrantUserToObjectOptions) (response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(grantUserToObjectOptions, "grantUserToObjectOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(grantUserToObjectOptions, "grantUserToObjectOptions")
	if err != nil {
		return
	}

	builder := core.NewRequestBuilder(core.POST)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = dataVirtualization.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(dataVirtualization.Service.Options.URL, `/v2/privileges/users`, nil)
	if err != nil {
		return
	}

	for headerName, headerValue := range grantUserToObjectOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("data_virtualization", "V1", "GrantUserToObject")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}
	builder.AddHeader("Content-Type", "application/json")

	body := make(map[string]interface{})
	if grantUserToObjectOptions.Body != nil {
		body["body"] = grantUserToObjectOptions.Body
	}
	_, err = builder.SetBodyContentJSON(body)
	if err != nil {
		return
	}

	request, err := builder.Build()
	if err != nil {
		return
	}

	response, err = dataVirtualization.Service.Request(request, nil)

	return
}

// RevokeUserFromObject : Revoke user acccess
// Revokes user access to the virtualized object.
func (dataVirtualization *DataVirtualizationV1) RevokeUserFromObject(revokeUserFromObjectOptions *RevokeUserFromObjectOptions) (response *core.DetailedResponse, err error) {
	return dataVirtualization.RevokeUserFromObjectWithContext(context.Background(), revokeUserFromObjectOptions)
}

// RevokeUserFromObjectWithContext is an alternate form of the RevokeUserFromObject method which supports a Context parameter
func (dataVirtualization *DataVirtualizationV1) RevokeUserFromObjectWithContext(ctx context.Context, revokeUserFromObjectOptions *RevokeUserFromObjectOptions) (response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(revokeUserFromObjectOptions, "revokeUserFromObjectOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(revokeUserFromObjectOptions, "revokeUserFromObjectOptions")
	if err != nil {
		return
	}

	builder := core.NewRequestBuilder(core.DELETE)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = dataVirtualization.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(dataVirtualization.Service.Options.URL, `/v2/privileges/users`, nil)
	if err != nil {
		return
	}

	for headerName, headerValue := range revokeUserFromObjectOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("data_virtualization", "V1", "RevokeUserFromObject")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}
	builder.AddHeader("Content-Type", "application/json")

	body := make(map[string]interface{})
	if revokeUserFromObjectOptions.Body != nil {
		body["body"] = revokeUserFromObjectOptions.Body
	}
	_, err = builder.SetBodyContentJSON(body)
	if err != nil {
		return
	}

	request, err := builder.Build()
	if err != nil {
		return
	}

	response, err = dataVirtualization.Service.Request(request, nil)

	return
}

// GrantRolesToVirtualizedTable : Grant user role
// Grants a user role access to a specific virtualized object.
func (dataVirtualization *DataVirtualizationV1) GrantRolesToVirtualizedTable(grantRolesToVirtualizedTableOptions *GrantRolesToVirtualizedTableOptions) (response *core.DetailedResponse, err error) {
	return dataVirtualization.GrantRolesToVirtualizedTableWithContext(context.Background(), grantRolesToVirtualizedTableOptions)
}

// GrantRolesToVirtualizedTableWithContext is an alternate form of the GrantRolesToVirtualizedTable method which supports a Context parameter
func (dataVirtualization *DataVirtualizationV1) GrantRolesToVirtualizedTableWithContext(ctx context.Context, grantRolesToVirtualizedTableOptions *GrantRolesToVirtualizedTableOptions) (response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(grantRolesToVirtualizedTableOptions, "grantRolesToVirtualizedTableOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(grantRolesToVirtualizedTableOptions, "grantRolesToVirtualizedTableOptions")
	if err != nil {
		return
	}

	builder := core.NewRequestBuilder(core.POST)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = dataVirtualization.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(dataVirtualization.Service.Options.URL, `/v2/privileges/roles`, nil)
	if err != nil {
		return
	}

	for headerName, headerValue := range grantRolesToVirtualizedTableOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("data_virtualization", "V1", "GrantRolesToVirtualizedTable")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddQuery("authid", fmt.Sprint(*grantRolesToVirtualizedTableOptions.Authid))
	builder.AddQuery("object_name", fmt.Sprint(*grantRolesToVirtualizedTableOptions.ObjectName))
	builder.AddQuery("object_schema", fmt.Sprint(*grantRolesToVirtualizedTableOptions.ObjectSchema))

	request, err := builder.Build()
	if err != nil {
		return
	}

	response, err = dataVirtualization.Service.Request(request, nil)

	return
}

// RevokeRoleFromObjectV2 : Delete role
// Revokes roles for a virtualized object.
func (dataVirtualization *DataVirtualizationV1) RevokeRoleFromObjectV2(revokeRoleFromObjectV2Options *RevokeRoleFromObjectV2Options) (response *core.DetailedResponse, err error) {
	return dataVirtualization.RevokeRoleFromObjectV2WithContext(context.Background(), revokeRoleFromObjectV2Options)
}

// RevokeRoleFromObjectV2WithContext is an alternate form of the RevokeRoleFromObjectV2 method which supports a Context parameter
func (dataVirtualization *DataVirtualizationV1) RevokeRoleFromObjectV2WithContext(ctx context.Context, revokeRoleFromObjectV2Options *RevokeRoleFromObjectV2Options) (response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(revokeRoleFromObjectV2Options, "revokeRoleFromObjectV2Options cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(revokeRoleFromObjectV2Options, "revokeRoleFromObjectV2Options")
	if err != nil {
		return
	}

	builder := core.NewRequestBuilder(core.DELETE)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = dataVirtualization.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(dataVirtualization.Service.Options.URL, `/v2/privileges/roles`, nil)
	if err != nil {
		return
	}

	for headerName, headerValue := range revokeRoleFromObjectV2Options.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("data_virtualization", "V1", "RevokeRoleFromObjectV2")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}
	builder.AddHeader("Content-Type", "application/json")

	body := make(map[string]interface{})
	if revokeRoleFromObjectV2Options.Body != nil {
		body["body"] = revokeRoleFromObjectV2Options.Body
	}
	_, err = builder.SetBodyContentJSON(body)
	if err != nil {
		return
	}

	request, err := builder.Build()
	if err != nil {
		return
	}

	response, err = dataVirtualization.Service.Request(request, nil)

	return
}

// GetObjectsForRole : Get objects by role
// Retrieves the list of virtualized objects that have a specific role.
func (dataVirtualization *DataVirtualizationV1) GetObjectsForRole(getObjectsForRoleOptions *GetObjectsForRoleOptions) (result *ObjectsForRoleResponse, response *core.DetailedResponse, err error) {
	return dataVirtualization.GetObjectsForRoleWithContext(context.Background(), getObjectsForRoleOptions)
}

// GetObjectsForRoleWithContext is an alternate form of the GetObjectsForRole method which supports a Context parameter
func (dataVirtualization *DataVirtualizationV1) GetObjectsForRoleWithContext(ctx context.Context, getObjectsForRoleOptions *GetObjectsForRoleOptions) (result *ObjectsForRoleResponse, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(getObjectsForRoleOptions, "getObjectsForRoleOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(getObjectsForRoleOptions, "getObjectsForRoleOptions")
	if err != nil {
		return
	}

	pathParamsMap := map[string]string{
		"rolename": *getObjectsForRoleOptions.Rolename,
	}

	builder := core.NewRequestBuilder(core.GET)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = dataVirtualization.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(dataVirtualization.Service.Options.URL, `/v1/privileges/objects/role/{rolename}`, pathParamsMap)
	if err != nil {
		return
	}

	for headerName, headerValue := range getObjectsForRoleOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("data_virtualization", "V1", "GetObjectsForRole")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}
	builder.AddHeader("Accept", "application/json")

	request, err := builder.Build()
	if err != nil {
		return
	}

	var rawResponse map[string]json.RawMessage
	response, err = dataVirtualization.Service.Request(request, &rawResponse)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(rawResponse, "", &result, UnmarshalObjectsForRoleResponse)
	if err != nil {
		return
	}
	response.Result = result

	return
}

// VirtualizeTableV2 : Virtualize table
// Transforms a given data source table into a virtualized table.
func (dataVirtualization *DataVirtualizationV1) VirtualizeTableV2(virtualizeTableV2Options *VirtualizeTableV2Options) (result *SuccessResponse, response *core.DetailedResponse, err error) {
	return dataVirtualization.VirtualizeTableV2WithContext(context.Background(), virtualizeTableV2Options)
}

// VirtualizeTableV2WithContext is an alternate form of the VirtualizeTableV2 method which supports a Context parameter
func (dataVirtualization *DataVirtualizationV1) VirtualizeTableV2WithContext(ctx context.Context, virtualizeTableV2Options *VirtualizeTableV2Options) (result *SuccessResponse, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(virtualizeTableV2Options, "virtualizeTableV2Options cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(virtualizeTableV2Options, "virtualizeTableV2Options")
	if err != nil {
		return
	}

	builder := core.NewRequestBuilder(core.POST)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = dataVirtualization.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(dataVirtualization.Service.Options.URL, `/v2/virtualize/tables`, nil)
	if err != nil {
		return
	}

	for headerName, headerValue := range virtualizeTableV2Options.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("data_virtualization", "V1", "VirtualizeTableV2")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}
	builder.AddHeader("Accept", "application/json")
	builder.AddHeader("Content-Type", "application/json")

	body := make(map[string]interface{})
	if virtualizeTableV2Options.SourceName != nil {
		body["source_name"] = virtualizeTableV2Options.SourceName
	}
	if virtualizeTableV2Options.SourceTableDef != nil {
		body["source_table_def"] = virtualizeTableV2Options.SourceTableDef
	}
	if virtualizeTableV2Options.Sources != nil {
		body["sources"] = virtualizeTableV2Options.Sources
	}
	if virtualizeTableV2Options.VirtualName != nil {
		body["virtual_name"] = virtualizeTableV2Options.VirtualName
	}
	if virtualizeTableV2Options.VirtualSchema != nil {
		body["virtual_schema"] = virtualizeTableV2Options.VirtualSchema
	}
	if virtualizeTableV2Options.VirtualTableDef != nil {
		body["virtual_table_def"] = virtualizeTableV2Options.VirtualTableDef
	}
	if virtualizeTableV2Options.IsIncludedColumns != nil {
		body["is_included_columns"] = virtualizeTableV2Options.IsIncludedColumns
	}
	if virtualizeTableV2Options.Replace != nil {
		body["replace"] = virtualizeTableV2Options.Replace
	}
	_, err = builder.SetBodyContentJSON(body)
	if err != nil {
		return
	}

	request, err := builder.Build()
	if err != nil {
		return
	}

	var rawResponse map[string]json.RawMessage
	response, err = dataVirtualization.Service.Request(request, &rawResponse)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(rawResponse, "", &result, UnmarshalSuccessResponse)
	if err != nil {
		return
	}
	response.Result = result

	return
}

// DeleteTable : Delete table
// Removes the specified table. You must specify the schema and table name.
func (dataVirtualization *DataVirtualizationV1) DeleteTable(deleteTableOptions *DeleteTableOptions) (response *core.DetailedResponse, err error) {
	return dataVirtualization.DeleteTableWithContext(context.Background(), deleteTableOptions)
}

// DeleteTableWithContext is an alternate form of the DeleteTable method which supports a Context parameter
func (dataVirtualization *DataVirtualizationV1) DeleteTableWithContext(ctx context.Context, deleteTableOptions *DeleteTableOptions) (response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(deleteTableOptions, "deleteTableOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(deleteTableOptions, "deleteTableOptions")
	if err != nil {
		return
	}

	pathParamsMap := map[string]string{
		"object_name": *deleteTableOptions.ObjectName,
	}

	builder := core.NewRequestBuilder(core.DELETE)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = dataVirtualization.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(dataVirtualization.Service.Options.URL, `/v2/mydata/tables/{object_name}`, pathParamsMap)
	if err != nil {
		return
	}

	for headerName, headerValue := range deleteTableOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("data_virtualization", "V1", "DeleteTable")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddQuery("schema_name", fmt.Sprint(*deleteTableOptions.SchemaName))

	request, err := builder.Build()
	if err != nil {
		return
	}

	response, err = dataVirtualization.Service.Request(request, nil)

	return
}

// AddDatasourceConnectionOptions : The AddDatasourceConnection options.
type AddDatasourceConnectionOptions struct {
	// The type of data source that you want to add.
	DatasourceType *string `json:"datasource_type" validate:"required"`

	// The name of data source.
	Name *string `json:"name" validate:"required"`

	// The location of data source that you want to add.
	OriginCountry *string `json:"origin_country" validate:"required"`

	Properties *PostDatasourceConnectionParametersV2Properties `json:"properties" validate:"required"`

	AssetCategory *string `json:"asset_category,omitempty"`

	// The remote connector to associate to the data source.
	RemoteNodes *string `json:"remote_nodes,omitempty"`

	// Allows users to set headers on API requests
	Headers map[string]string
}

// NewAddDatasourceConnectionOptions : Instantiate AddDatasourceConnectionOptions
func (*DataVirtualizationV1) NewAddDatasourceConnectionOptions(datasourceType string, name string, originCountry string, properties *PostDatasourceConnectionParametersV2Properties) *AddDatasourceConnectionOptions {
	return &AddDatasourceConnectionOptions{
		DatasourceType: core.StringPtr(datasourceType),
		Name: core.StringPtr(name),
		OriginCountry: core.StringPtr(originCountry),
		Properties: properties,
	}
}

// SetDatasourceType : Allow user to set DatasourceType
func (options *AddDatasourceConnectionOptions) SetDatasourceType(datasourceType string) *AddDatasourceConnectionOptions {
	options.DatasourceType = core.StringPtr(datasourceType)
	return options
}

// SetName : Allow user to set Name
func (options *AddDatasourceConnectionOptions) SetName(name string) *AddDatasourceConnectionOptions {
	options.Name = core.StringPtr(name)
	return options
}

// SetOriginCountry : Allow user to set OriginCountry
func (options *AddDatasourceConnectionOptions) SetOriginCountry(originCountry string) *AddDatasourceConnectionOptions {
	options.OriginCountry = core.StringPtr(originCountry)
	return options
}

// SetProperties : Allow user to set Properties
func (options *AddDatasourceConnectionOptions) SetProperties(properties *PostDatasourceConnectionParametersV2Properties) *AddDatasourceConnectionOptions {
	options.Properties = properties
	return options
}

// SetAssetCategory : Allow user to set AssetCategory
func (options *AddDatasourceConnectionOptions) SetAssetCategory(assetCategory string) *AddDatasourceConnectionOptions {
	options.AssetCategory = core.StringPtr(assetCategory)
	return options
}

// SetRemoteNodes : Allow user to set RemoteNodes
func (options *AddDatasourceConnectionOptions) SetRemoteNodes(remoteNodes string) *AddDatasourceConnectionOptions {
	options.RemoteNodes = core.StringPtr(remoteNodes)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *AddDatasourceConnectionOptions) SetHeaders(param map[string]string) *AddDatasourceConnectionOptions {
	options.Headers = param
	return options
}

// DatasourceNodesResponseV2DatasourceNodesArrayItem : DatasourceNodesResponseV2DatasourceNodesArrayItem struct
type DatasourceNodesResponseV2DatasourceNodesArrayItem struct {
	// The name of the node.
	NodeName *string `json:"node_name,omitempty"`

	// The description of the node.
	NodeDescription *string `json:"node_description,omitempty"`

	// The type of connector, which includes internal connector and remote connector.
	AgentClass *string `json:"agent_class,omitempty"`

	// The hostname or IP address that is used to access the connection.
	Hostname *string `json:"hostname,omitempty"`

	// The port number that is used to access the connection.
	Port *string `json:"port,omitempty"`

	OsUser *string `json:"os_user,omitempty"`

	// Determines whether the data source uses Docker.
	IsDocker *string `json:"is_docker,omitempty"`

	// The number of data sources.
	Dscount *string `json:"dscount,omitempty"`

	DataSources []DatasourceNodesResponseV2DatasourceNodesArrayItemDataSourcesItem `json:"data_sources,omitempty"`
}


// UnmarshalDatasourceNodesResponseV2DatasourceNodesArrayItem unmarshals an instance of DatasourceNodesResponseV2DatasourceNodesArrayItem from the specified map of raw messages.
func UnmarshalDatasourceNodesResponseV2DatasourceNodesArrayItem(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(DatasourceNodesResponseV2DatasourceNodesArrayItem)
	err = core.UnmarshalPrimitive(m, "node_name", &obj.NodeName)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "node_description", &obj.NodeDescription)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "agent_class", &obj.AgentClass)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "hostname", &obj.Hostname)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "port", &obj.Port)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "os_user", &obj.OsUser)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "is_docker", &obj.IsDocker)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "dscount", &obj.Dscount)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "data_sources", &obj.DataSources, UnmarshalDatasourceNodesResponseV2DatasourceNodesArrayItemDataSourcesItem)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// DatasourceNodesResponseV2DatasourceNodesArrayItemDataSourcesItem : DatasourceNodesResponseV2DatasourceNodesArrayItemDataSourcesItem struct
type DatasourceNodesResponseV2DatasourceNodesArrayItemDataSourcesItem struct {
	// The identifier of the connection.
	Cid *string `json:"cid,omitempty"`

	// The name of the database.
	Dbname *string `json:"dbname,omitempty"`

	// The hostname or IP address of the data source.
	Srchostname *string `json:"srchostname,omitempty"`

	// The port number of the data source.
	Srcport *string `json:"srcport,omitempty"`

	// The type of the data source.
	Srctype *string `json:"srctype,omitempty"`

	// The user that has access to the data source.
	Usr *string `json:"usr,omitempty"`

	// The URI of the data source.
	URI *string `json:"uri,omitempty"`

	// The status of the data source.
	Status *string `json:"status,omitempty"`

	// The name of the connection.
	ConnectionName *string `json:"connection_name,omitempty"`
}


// UnmarshalDatasourceNodesResponseV2DatasourceNodesArrayItemDataSourcesItem unmarshals an instance of DatasourceNodesResponseV2DatasourceNodesArrayItemDataSourcesItem from the specified map of raw messages.
func UnmarshalDatasourceNodesResponseV2DatasourceNodesArrayItemDataSourcesItem(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(DatasourceNodesResponseV2DatasourceNodesArrayItemDataSourcesItem)
	err = core.UnmarshalPrimitive(m, "cid", &obj.Cid)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "dbname", &obj.Dbname)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "srchostname", &obj.Srchostname)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "srcport", &obj.Srcport)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "srctype", &obj.Srctype)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "usr", &obj.Usr)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "uri", &obj.URI)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "status", &obj.Status)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "connection_name", &obj.ConnectionName)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// DatasourceNodesResponseV2 : DatasourceNodesResponseV2 struct
type DatasourceNodesResponseV2 struct {
	DatasourceNodesArray []DatasourceNodesResponseV2DatasourceNodesArrayItem `json:"datasource_nodes_array,omitempty"`
}


// UnmarshalDatasourceNodesResponseV2 unmarshals an instance of DatasourceNodesResponseV2 from the specified map of raw messages.
func UnmarshalDatasourceNodesResponseV2(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(DatasourceNodesResponseV2)
	err = core.UnmarshalModel(m, "datasource_nodes_array", &obj.DatasourceNodesArray, UnmarshalDatasourceNodesResponseV2DatasourceNodesArrayItem)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// DeleteDatasourceConnectionOptions : The DeleteDatasourceConnection options.
type DeleteDatasourceConnectionOptions struct {
	// The identifier of the connection.
	Cid *string `json:"cid" validate:"required"`

	// The name of the connection.
	ConnectionID *string `json:"connection_id" validate:"required"`

	// Allows users to set headers on API requests
	Headers map[string]string
}

// NewDeleteDatasourceConnectionOptions : Instantiate DeleteDatasourceConnectionOptions
func (*DataVirtualizationV1) NewDeleteDatasourceConnectionOptions(cid string, connectionID string) *DeleteDatasourceConnectionOptions {
	return &DeleteDatasourceConnectionOptions{
		Cid: core.StringPtr(cid),
		ConnectionID: core.StringPtr(connectionID),
	}
}

// SetCid : Allow user to set Cid
func (options *DeleteDatasourceConnectionOptions) SetCid(cid string) *DeleteDatasourceConnectionOptions {
	options.Cid = core.StringPtr(cid)
	return options
}

// SetConnectionID : Allow user to set ConnectionID
func (options *DeleteDatasourceConnectionOptions) SetConnectionID(connectionID string) *DeleteDatasourceConnectionOptions {
	options.ConnectionID = core.StringPtr(connectionID)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *DeleteDatasourceConnectionOptions) SetHeaders(param map[string]string) *DeleteDatasourceConnectionOptions {
	options.Headers = param
	return options
}

// DeleteTableOptions : The DeleteTable options.
type DeleteTableOptions struct {
	// The schema of table or view to be deleted.
	SchemaName *string `json:"schema_name" validate:"required"`

	// The name of table or view to be deleted.
	ObjectName *string `json:"object_name" validate:"required,ne="`

	// Allows users to set headers on API requests
	Headers map[string]string
}

// NewDeleteTableOptions : Instantiate DeleteTableOptions
func (*DataVirtualizationV1) NewDeleteTableOptions(schemaName string, objectName string) *DeleteTableOptions {
	return &DeleteTableOptions{
		SchemaName: core.StringPtr(schemaName),
		ObjectName: core.StringPtr(objectName),
	}
}

// SetSchemaName : Allow user to set SchemaName
func (options *DeleteTableOptions) SetSchemaName(schemaName string) *DeleteTableOptions {
	options.SchemaName = core.StringPtr(schemaName)
	return options
}

// SetObjectName : Allow user to set ObjectName
func (options *DeleteTableOptions) SetObjectName(objectName string) *DeleteTableOptions {
	options.ObjectName = core.StringPtr(objectName)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *DeleteTableOptions) SetHeaders(param map[string]string) *DeleteTableOptions {
	options.Headers = param
	return options
}

// GetDatasourceNodesOptions : The GetDatasourceNodes options.
type GetDatasourceNodesOptions struct {

	// Allows users to set headers on API requests
	Headers map[string]string
}

// NewGetDatasourceNodesOptions : Instantiate GetDatasourceNodesOptions
func (*DataVirtualizationV1) NewGetDatasourceNodesOptions() *GetDatasourceNodesOptions {
	return &GetDatasourceNodesOptions{}
}

// SetHeaders : Allow user to set Headers
func (options *GetDatasourceNodesOptions) SetHeaders(param map[string]string) *GetDatasourceNodesOptions {
	options.Headers = param
	return options
}

// GetObjectsForRoleOptions : The GetObjectsForRole options.
type GetObjectsForRoleOptions struct {
	// Data Virtualization has four roles: ADMIN, STEWARD, ENGINEER and USER The value of rolename should be one of them.
	Rolename *string `json:"rolename" validate:"required,ne="`

	// Allows users to set headers on API requests
	Headers map[string]string
}

// NewGetObjectsForRoleOptions : Instantiate GetObjectsForRoleOptions
func (*DataVirtualizationV1) NewGetObjectsForRoleOptions(rolename string) *GetObjectsForRoleOptions {
	return &GetObjectsForRoleOptions{
		Rolename: core.StringPtr(rolename),
	}
}

// SetRolename : Allow user to set Rolename
func (options *GetObjectsForRoleOptions) SetRolename(rolename string) *GetObjectsForRoleOptions {
	options.Rolename = core.StringPtr(rolename)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *GetObjectsForRoleOptions) SetHeaders(param map[string]string) *GetObjectsForRoleOptions {
	options.Headers = param
	return options
}

// GrantRolesToVirtualizedTableOptions : The GrantRolesToVirtualizedTable options.
type GrantRolesToVirtualizedTableOptions struct {
	// Authentication ID.
	Authid *string `json:"authid" validate:"required"`

	// Object name to be deleleted.
	ObjectName *string `json:"object_name" validate:"required"`

	// Object schema name.
	ObjectSchema *string `json:"object_schema" validate:"required"`

	// Allows users to set headers on API requests
	Headers map[string]string
}

// NewGrantRolesToVirtualizedTableOptions : Instantiate GrantRolesToVirtualizedTableOptions
func (*DataVirtualizationV1) NewGrantRolesToVirtualizedTableOptions(authid string, objectName string, objectSchema string) *GrantRolesToVirtualizedTableOptions {
	return &GrantRolesToVirtualizedTableOptions{
		Authid: core.StringPtr(authid),
		ObjectName: core.StringPtr(objectName),
		ObjectSchema: core.StringPtr(objectSchema),
	}
}

// SetAuthid : Allow user to set Authid
func (options *GrantRolesToVirtualizedTableOptions) SetAuthid(authid string) *GrantRolesToVirtualizedTableOptions {
	options.Authid = core.StringPtr(authid)
	return options
}

// SetObjectName : Allow user to set ObjectName
func (options *GrantRolesToVirtualizedTableOptions) SetObjectName(objectName string) *GrantRolesToVirtualizedTableOptions {
	options.ObjectName = core.StringPtr(objectName)
	return options
}

// SetObjectSchema : Allow user to set ObjectSchema
func (options *GrantRolesToVirtualizedTableOptions) SetObjectSchema(objectSchema string) *GrantRolesToVirtualizedTableOptions {
	options.ObjectSchema = core.StringPtr(objectSchema)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *GrantRolesToVirtualizedTableOptions) SetHeaders(param map[string]string) *GrantRolesToVirtualizedTableOptions {
	options.Headers = param
	return options
}

// GrantUserToObjectOptions : The GrantUserToObject options.
type GrantUserToObjectOptions struct {
	Body []GrantUserToObjectRequestBodyItem `json:"body" validate:"required"`

	// Allows users to set headers on API requests
	Headers map[string]string
}

// NewGrantUserToObjectOptions : Instantiate GrantUserToObjectOptions
func (*DataVirtualizationV1) NewGrantUserToObjectOptions(body []GrantUserToObjectRequestBodyItem) *GrantUserToObjectOptions {
	return &GrantUserToObjectOptions{
		Body: body,
	}
}

// SetBody : Allow user to set Body
func (options *GrantUserToObjectOptions) SetBody(body []GrantUserToObjectRequestBodyItem) *GrantUserToObjectOptions {
	options.Body = body
	return options
}

// SetHeaders : Allow user to set Headers
func (options *GrantUserToObjectOptions) SetHeaders(param map[string]string) *GrantUserToObjectOptions {
	options.Headers = param
	return options
}

// GrantUserToObjectRequestBodyItem : GrantUserToObjectRequestBodyItem struct
type GrantUserToObjectRequestBodyItem struct {
	// The name of the virtualized object.
	ObjectName *string `json:"object_name,omitempty"`

	// The schema of the virtualized object.
	ObjectSchema *string `json:"object_schema,omitempty"`

	// The identifier of the authorization, if grant access to all users, the value is PUBLIC, othervise the value is the
	// data virtualization username.
	Authid *string `json:"authid,omitempty"`
}


// UnmarshalGrantUserToObjectRequestBodyItem unmarshals an instance of GrantUserToObjectRequestBodyItem from the specified map of raw messages.
func UnmarshalGrantUserToObjectRequestBodyItem(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(GrantUserToObjectRequestBodyItem)
	err = core.UnmarshalPrimitive(m, "object_name", &obj.ObjectName)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "object_schema", &obj.ObjectSchema)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "authid", &obj.Authid)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// ObjectsForRoleResponse : ObjectsForRoleResponse struct
type ObjectsForRoleResponse struct {
	Objects []ObjectsForRoleResponseObjectsItem `json:"objects,omitempty"`
}


// UnmarshalObjectsForRoleResponse unmarshals an instance of ObjectsForRoleResponse from the specified map of raw messages.
func UnmarshalObjectsForRoleResponse(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(ObjectsForRoleResponse)
	err = core.UnmarshalModel(m, "objects", &obj.Objects, UnmarshalObjectsForRoleResponseObjectsItem)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// ObjectsForRoleResponseObjectsItem : ObjectsForRoleResponseObjectsItem struct
type ObjectsForRoleResponseObjectsItem struct {
	// The table or view name that is granted access to role ROLENAME.
	ObjectName *string `json:"object_name,omitempty"`

	// The SCHEMA of table or view that is granted access to role ROLENAME.
	ObjectSchema *string `json:"object_schema,omitempty"`

	// The value show the object is a TABLE or VIEW.
	ObjectType *string `json:"object_type,omitempty"`
}


// UnmarshalObjectsForRoleResponseObjectsItem unmarshals an instance of ObjectsForRoleResponseObjectsItem from the specified map of raw messages.
func UnmarshalObjectsForRoleResponseObjectsItem(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(ObjectsForRoleResponseObjectsItem)
	err = core.UnmarshalPrimitive(m, "object_name", &obj.ObjectName)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "object_schema", &obj.ObjectSchema)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "object_type", &obj.ObjectType)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// PostDatasourceConnectionParametersV2Properties : PostDatasourceConnectionParametersV2Properties struct
type PostDatasourceConnectionParametersV2Properties struct {
	AccessToken *string `json:"access_token,omitempty"`

	AccountName *string `json:"account_name,omitempty"`

	ApiKey *string `json:"api_key,omitempty"`

	AuthType *string `json:"auth_type,omitempty"`

	ClientID *string `json:"client_id,omitempty"`

	ClientSecret *string `json:"client_secret,omitempty"`

	Credentials *string `json:"credentials,omitempty"`

	Database *string `json:"database,omitempty"`

	Host *string `json:"host,omitempty"`

	HttpPath *string `json:"http_path,omitempty"`

	JarUris *string `json:"jar_uris,omitempty"`

	JdbcDriver *string `json:"jdbc_driver,omitempty"`

	JdbcURL *string `json:"jdbc_url,omitempty"`

	Password *string `json:"password,omitempty"`

	Port *string `json:"port,omitempty"`

	ProjectID *string `json:"project_id,omitempty"`

	Properties *string `json:"properties,omitempty"`

	RefreshToken *string `json:"refresh_token,omitempty"`

	SapGatewayURL *string `json:"sap_gateway_url,omitempty"`

	Server *string `json:"server,omitempty"`

	ServiceName *string `json:"service_name,omitempty"`

	Sid *string `json:"sid,omitempty"`

	Ssl *string `json:"ssl,omitempty"`

	SslCertificate *string `json:"ssl_certificate,omitempty"`

	SslCertificateHost *string `json:"ssl_certificate_host,omitempty"`

	SslCertificateValidation *string `json:"ssl_certificate_validation,omitempty"`

	Username *string `json:"username,omitempty"`

	Warehouse *string `json:"warehouse,omitempty"`
}


// UnmarshalPostDatasourceConnectionParametersV2Properties unmarshals an instance of PostDatasourceConnectionParametersV2Properties from the specified map of raw messages.
func UnmarshalPostDatasourceConnectionParametersV2Properties(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(PostDatasourceConnectionParametersV2Properties)
	err = core.UnmarshalPrimitive(m, "access_token", &obj.AccessToken)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "account_name", &obj.AccountName)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "api_key", &obj.ApiKey)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "auth_type", &obj.AuthType)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "client_id", &obj.ClientID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "client_secret", &obj.ClientSecret)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "credentials", &obj.Credentials)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "database", &obj.Database)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "host", &obj.Host)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "http_path", &obj.HttpPath)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "jar_uris", &obj.JarUris)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "jdbc_driver", &obj.JdbcDriver)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "jdbc_url", &obj.JdbcURL)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "password", &obj.Password)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "port", &obj.Port)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "project_id", &obj.ProjectID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "properties", &obj.Properties)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "refresh_token", &obj.RefreshToken)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "sap_gateway_url", &obj.SapGatewayURL)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "server", &obj.Server)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "service_name", &obj.ServiceName)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "sid", &obj.Sid)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "ssl", &obj.Ssl)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "ssl_certificate", &obj.SslCertificate)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "ssl_certificate_host", &obj.SslCertificateHost)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "ssl_certificate_validation", &obj.SslCertificateValidation)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "username", &obj.Username)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "warehouse", &obj.Warehouse)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// RevokeRoleFromObjectV2Options : The RevokeRoleFromObjectV2 options.
type RevokeRoleFromObjectV2Options struct {
	Body []RevokeRoleFromObjectV2RequestBodyItem `json:"body,omitempty"`

	// Allows users to set headers on API requests
	Headers map[string]string
}

// NewRevokeRoleFromObjectV2Options : Instantiate RevokeRoleFromObjectV2Options
func (*DataVirtualizationV1) NewRevokeRoleFromObjectV2Options() *RevokeRoleFromObjectV2Options {
	return &RevokeRoleFromObjectV2Options{}
}

// SetBody : Allow user to set Body
func (options *RevokeRoleFromObjectV2Options) SetBody(body []RevokeRoleFromObjectV2RequestBodyItem) *RevokeRoleFromObjectV2Options {
	options.Body = body
	return options
}

// SetHeaders : Allow user to set Headers
func (options *RevokeRoleFromObjectV2Options) SetHeaders(param map[string]string) *RevokeRoleFromObjectV2Options {
	options.Headers = param
	return options
}

// RevokeRoleFromObjectV2RequestBodyItem : RevokeRoleFromObjectV2RequestBodyItem struct
type RevokeRoleFromObjectV2RequestBodyItem struct {
	// The name of the virtual object.
	ObjectName *string `json:"object_name,omitempty"`

	// The schema of the virtual object.
	ObjectSchema *string `json:"object_schema,omitempty"`

	// The role to revoke from the user.
	RoleToRevoke *string `json:"role_to_revoke,omitempty"`
}


// UnmarshalRevokeRoleFromObjectV2RequestBodyItem unmarshals an instance of RevokeRoleFromObjectV2RequestBodyItem from the specified map of raw messages.
func UnmarshalRevokeRoleFromObjectV2RequestBodyItem(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(RevokeRoleFromObjectV2RequestBodyItem)
	err = core.UnmarshalPrimitive(m, "object_name", &obj.ObjectName)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "object_schema", &obj.ObjectSchema)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "role_to_revoke", &obj.RoleToRevoke)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// RevokeUserFromObjectOptions : The RevokeUserFromObject options.
type RevokeUserFromObjectOptions struct {
	Body []RevokeUserFromObjectRequestBodyItem `json:"body" validate:"required"`

	// Allows users to set headers on API requests
	Headers map[string]string
}

// NewRevokeUserFromObjectOptions : Instantiate RevokeUserFromObjectOptions
func (*DataVirtualizationV1) NewRevokeUserFromObjectOptions(body []RevokeUserFromObjectRequestBodyItem) *RevokeUserFromObjectOptions {
	return &RevokeUserFromObjectOptions{
		Body: body,
	}
}

// SetBody : Allow user to set Body
func (options *RevokeUserFromObjectOptions) SetBody(body []RevokeUserFromObjectRequestBodyItem) *RevokeUserFromObjectOptions {
	options.Body = body
	return options
}

// SetHeaders : Allow user to set Headers
func (options *RevokeUserFromObjectOptions) SetHeaders(param map[string]string) *RevokeUserFromObjectOptions {
	options.Headers = param
	return options
}

// RevokeUserFromObjectRequestBodyItem : RevokeUserFromObjectRequestBodyItem struct
type RevokeUserFromObjectRequestBodyItem struct {
	// The name of the virtual object.
	ObjectName *string `json:"object_name,omitempty"`

	// The schema of the virtual object.
	ObjectSchema *string `json:"object_schema,omitempty"`

	// The identifier of the authorization.
	Authid *string `json:"authid,omitempty"`
}


// UnmarshalRevokeUserFromObjectRequestBodyItem unmarshals an instance of RevokeUserFromObjectRequestBodyItem from the specified map of raw messages.
func UnmarshalRevokeUserFromObjectRequestBodyItem(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(RevokeUserFromObjectRequestBodyItem)
	err = core.UnmarshalPrimitive(m, "object_name", &obj.ObjectName)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "object_schema", &obj.ObjectSchema)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "authid", &obj.Authid)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// VirtualizeTableV2Options : The VirtualizeTableV2 options.
type VirtualizeTableV2Options struct {
	// The name of the source table.
	SourceName *string `json:"source_name" validate:"required"`

	SourceTableDef []VirtualizeTableV2RequestSourceTableDefItem `json:"source_table_def" validate:"required"`

	Sources []string `json:"sources" validate:"required"`

	// The name of the table that will be virtualized.
	VirtualName *string `json:"virtual_name" validate:"required"`

	// The schema of the table that will be virtualized.
	VirtualSchema *string `json:"virtual_schema" validate:"required"`

	VirtualTableDef []VirtualizeTableV2RequestVirtualTableDefItem `json:"virtual_table_def" validate:"required"`

	// The columns that are included in the table.
	IsIncludedColumns *string `json:"is_included_columns,omitempty"`

	// Determines whether to replace columns in the virtualized table.
	Replace *bool `json:"replace,omitempty"`

	// Allows users to set headers on API requests
	Headers map[string]string
}

// NewVirtualizeTableV2Options : Instantiate VirtualizeTableV2Options
func (*DataVirtualizationV1) NewVirtualizeTableV2Options(sourceName string, sourceTableDef []VirtualizeTableV2RequestSourceTableDefItem, sources []string, virtualName string, virtualSchema string, virtualTableDef []VirtualizeTableV2RequestVirtualTableDefItem) *VirtualizeTableV2Options {
	return &VirtualizeTableV2Options{
		SourceName: core.StringPtr(sourceName),
		SourceTableDef: sourceTableDef,
		Sources: sources,
		VirtualName: core.StringPtr(virtualName),
		VirtualSchema: core.StringPtr(virtualSchema),
		VirtualTableDef: virtualTableDef,
	}
}

// SetSourceName : Allow user to set SourceName
func (options *VirtualizeTableV2Options) SetSourceName(sourceName string) *VirtualizeTableV2Options {
	options.SourceName = core.StringPtr(sourceName)
	return options
}

// SetSourceTableDef : Allow user to set SourceTableDef
func (options *VirtualizeTableV2Options) SetSourceTableDef(sourceTableDef []VirtualizeTableV2RequestSourceTableDefItem) *VirtualizeTableV2Options {
	options.SourceTableDef = sourceTableDef
	return options
}

// SetSources : Allow user to set Sources
func (options *VirtualizeTableV2Options) SetSources(sources []string) *VirtualizeTableV2Options {
	options.Sources = sources
	return options
}

// SetVirtualName : Allow user to set VirtualName
func (options *VirtualizeTableV2Options) SetVirtualName(virtualName string) *VirtualizeTableV2Options {
	options.VirtualName = core.StringPtr(virtualName)
	return options
}

// SetVirtualSchema : Allow user to set VirtualSchema
func (options *VirtualizeTableV2Options) SetVirtualSchema(virtualSchema string) *VirtualizeTableV2Options {
	options.VirtualSchema = core.StringPtr(virtualSchema)
	return options
}

// SetVirtualTableDef : Allow user to set VirtualTableDef
func (options *VirtualizeTableV2Options) SetVirtualTableDef(virtualTableDef []VirtualizeTableV2RequestVirtualTableDefItem) *VirtualizeTableV2Options {
	options.VirtualTableDef = virtualTableDef
	return options
}

// SetIsIncludedColumns : Allow user to set IsIncludedColumns
func (options *VirtualizeTableV2Options) SetIsIncludedColumns(isIncludedColumns string) *VirtualizeTableV2Options {
	options.IsIncludedColumns = core.StringPtr(isIncludedColumns)
	return options
}

// SetReplace : Allow user to set Replace
func (options *VirtualizeTableV2Options) SetReplace(replace bool) *VirtualizeTableV2Options {
	options.Replace = core.BoolPtr(replace)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *VirtualizeTableV2Options) SetHeaders(param map[string]string) *VirtualizeTableV2Options {
	options.Headers = param
	return options
}

// VirtualizeTableV2RequestSourceTableDefItem : VirtualizeTableV2RequestSourceTableDefItem struct
type VirtualizeTableV2RequestSourceTableDefItem struct {
	// The name of the column.
	ColumnName *string `json:"column_name" validate:"required"`

	// The type of the column.
	ColumnType *string `json:"column_type" validate:"required"`
}


// NewVirtualizeTableV2RequestSourceTableDefItem : Instantiate VirtualizeTableV2RequestSourceTableDefItem (Generic Model Constructor)
func (*DataVirtualizationV1) NewVirtualizeTableV2RequestSourceTableDefItem(columnName string, columnType string) (model *VirtualizeTableV2RequestSourceTableDefItem, err error) {
	model = &VirtualizeTableV2RequestSourceTableDefItem{
		ColumnName: core.StringPtr(columnName),
		ColumnType: core.StringPtr(columnType),
	}
	err = core.ValidateStruct(model, "required parameters")
	return
}

// UnmarshalVirtualizeTableV2RequestSourceTableDefItem unmarshals an instance of VirtualizeTableV2RequestSourceTableDefItem from the specified map of raw messages.
func UnmarshalVirtualizeTableV2RequestSourceTableDefItem(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(VirtualizeTableV2RequestSourceTableDefItem)
	err = core.UnmarshalPrimitive(m, "column_name", &obj.ColumnName)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "column_type", &obj.ColumnType)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// VirtualizeTableV2RequestVirtualTableDefItem : VirtualizeTableV2RequestVirtualTableDefItem struct
type VirtualizeTableV2RequestVirtualTableDefItem struct {
	// The name of the column.
	ColumnName *string `json:"column_name" validate:"required"`

	// The type of the column.
	ColumnType *string `json:"column_type" validate:"required"`
}


// NewVirtualizeTableV2RequestVirtualTableDefItem : Instantiate VirtualizeTableV2RequestVirtualTableDefItem (Generic Model Constructor)
func (*DataVirtualizationV1) NewVirtualizeTableV2RequestVirtualTableDefItem(columnName string, columnType string) (model *VirtualizeTableV2RequestVirtualTableDefItem, err error) {
	model = &VirtualizeTableV2RequestVirtualTableDefItem{
		ColumnName: core.StringPtr(columnName),
		ColumnType: core.StringPtr(columnType),
	}
	err = core.ValidateStruct(model, "required parameters")
	return
}

// UnmarshalVirtualizeTableV2RequestVirtualTableDefItem unmarshals an instance of VirtualizeTableV2RequestVirtualTableDefItem from the specified map of raw messages.
func UnmarshalVirtualizeTableV2RequestVirtualTableDefItem(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(VirtualizeTableV2RequestVirtualTableDefItem)
	err = core.UnmarshalPrimitive(m, "column_name", &obj.ColumnName)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "column_type", &obj.ColumnType)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// SuccessResponse : SuccessResponse struct
type SuccessResponse struct {
	Message *string `json:"message" validate:"required"`
}


// UnmarshalSuccessResponse unmarshals an instance of SuccessResponse from the specified map of raw messages.
func UnmarshalSuccessResponse(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(SuccessResponse)
	err = core.UnmarshalPrimitive(m, "message", &obj.Message)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}
