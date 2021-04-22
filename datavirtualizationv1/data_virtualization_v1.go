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
	"github.com/IBM/go-sdk-core/v4/core"
	common "github.com/watson-developer-cloud/go-sdk/common"
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

// GetDatasourceConnections : Get data source connections
// Gets all data source connections that are connected to the service.
func (dataVirtualization *DataVirtualizationV1) GetDatasourceConnections(getDatasourceConnectionsOptions *GetDatasourceConnectionsOptions) (result *DatasourceNodesResponseV2, response *core.DetailedResponse, err error) {
	return dataVirtualization.GetDatasourceConnectionsWithContext(context.Background(), getDatasourceConnectionsOptions)
}

// GetDatasourceConnectionsWithContext is an alternate form of the GetDatasourceConnections method which supports a Context parameter
func (dataVirtualization *DataVirtualizationV1) GetDatasourceConnectionsWithContext(ctx context.Context, getDatasourceConnectionsOptions *GetDatasourceConnectionsOptions) (result *DatasourceNodesResponseV2, response *core.DetailedResponse, err error) {
	err = core.ValidateStruct(getDatasourceConnectionsOptions, "getDatasourceConnectionsOptions")
	if err != nil {
		return
	}

	builder := core.NewRequestBuilder(core.GET)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = dataVirtualization.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(dataVirtualization.Service.Options.URL, `/v2/datasource_connections`, nil)
	if err != nil {
		return
	}

	for headerName, headerValue := range getDatasourceConnectionsOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("data_virtualization", "V1", "GetDatasourceConnections")
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

// AddDatasourceConnection : Add data source connection
// Adds a data source connection to the Data Virtualization service.
func (dataVirtualization *DataVirtualizationV1) AddDatasourceConnection(addDatasourceConnectionOptions *AddDatasourceConnectionOptions) (result *PostDatasourceConnectionResponse, response *core.DetailedResponse, err error) {
	return dataVirtualization.AddDatasourceConnectionWithContext(context.Background(), addDatasourceConnectionOptions)
}

// AddDatasourceConnectionWithContext is an alternate form of the AddDatasourceConnection method which supports a Context parameter
func (dataVirtualization *DataVirtualizationV1) AddDatasourceConnectionWithContext(ctx context.Context, addDatasourceConnectionOptions *AddDatasourceConnectionOptions) (result *PostDatasourceConnectionResponse, response *core.DetailedResponse, err error) {
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
	builder.AddHeader("Accept", "application/json")
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
	err = core.UnmarshalModel(rawResponse, "", &result, UnmarshalPostDatasourceConnectionResponse)
	if err != nil {
		return
	}
	response.Result = result

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

	builder.AddQuery("cid", fmt.Sprint(*deleteDatasourceConnectionOptions.Cid))
	builder.AddQuery("connection_id", fmt.Sprint(*deleteDatasourceConnectionOptions.ConnectionID))

	request, err := builder.Build()
	if err != nil {
		return
	}

	response, err = dataVirtualization.Service.Request(request, nil)

	return
}

// GrantUserToVirtualTable : Grant user access
// Grants a user access to a specific virtualized table.
func (dataVirtualization *DataVirtualizationV1) GrantUserToVirtualTable(grantUserToVirtualTableOptions *GrantUserToVirtualTableOptions) (response *core.DetailedResponse, err error) {
	return dataVirtualization.GrantUserToVirtualTableWithContext(context.Background(), grantUserToVirtualTableOptions)
}

// GrantUserToVirtualTableWithContext is an alternate form of the GrantUserToVirtualTable method which supports a Context parameter
func (dataVirtualization *DataVirtualizationV1) GrantUserToVirtualTableWithContext(ctx context.Context, grantUserToVirtualTableOptions *GrantUserToVirtualTableOptions) (response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(grantUserToVirtualTableOptions, "grantUserToVirtualTableOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(grantUserToVirtualTableOptions, "grantUserToVirtualTableOptions")
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

	for headerName, headerValue := range grantUserToVirtualTableOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("data_virtualization", "V1", "GrantUserToVirtualTable")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}
	builder.AddHeader("Content-Type", "application/json")

	body := make(map[string]interface{})
	if grantUserToVirtualTableOptions.Body != nil {
		body["body"] = grantUserToVirtualTableOptions.Body
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
// Revokes user access to the virtualized table.
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

	builder.AddQuery("authid", fmt.Sprint(*revokeUserFromObjectOptions.Authid))
	builder.AddQuery("table_name", fmt.Sprint(*revokeUserFromObjectOptions.TableName))
	builder.AddQuery("table_schema", fmt.Sprint(*revokeUserFromObjectOptions.TableSchema))

	request, err := builder.Build()
	if err != nil {
		return
	}

	response, err = dataVirtualization.Service.Request(request, nil)

	return
}

// GrantRolesToVirtualizedTable : Grant user role
// Grants a user role access to a specific virtualized table.
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
	builder.AddHeader("Content-Type", "application/json")

	body := make(map[string]interface{})
	if grantRolesToVirtualizedTableOptions.Body != nil {
		body["body"] = grantRolesToVirtualizedTableOptions.Body
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

// RevokeRoleFromTableV2 : Delete role
// Revokes roles for a virtualized table.
func (dataVirtualization *DataVirtualizationV1) RevokeRoleFromTableV2(revokeRoleFromTableV2Options *RevokeRoleFromTableV2Options) (response *core.DetailedResponse, err error) {
	return dataVirtualization.RevokeRoleFromTableV2WithContext(context.Background(), revokeRoleFromTableV2Options)
}

// RevokeRoleFromTableV2WithContext is an alternate form of the RevokeRoleFromTableV2 method which supports a Context parameter
func (dataVirtualization *DataVirtualizationV1) RevokeRoleFromTableV2WithContext(ctx context.Context, revokeRoleFromTableV2Options *RevokeRoleFromTableV2Options) (response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(revokeRoleFromTableV2Options, "revokeRoleFromTableV2Options cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(revokeRoleFromTableV2Options, "revokeRoleFromTableV2Options")
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

	for headerName, headerValue := range revokeRoleFromTableV2Options.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("data_virtualization", "V1", "RevokeRoleFromTableV2")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddQuery("role_to_revoke", fmt.Sprint(*revokeRoleFromTableV2Options.RoleToRevoke))
	builder.AddQuery("table_name", fmt.Sprint(*revokeRoleFromTableV2Options.TableName))
	builder.AddQuery("table_schema", fmt.Sprint(*revokeRoleFromTableV2Options.TableSchema))

	request, err := builder.Build()
	if err != nil {
		return
	}

	response, err = dataVirtualization.Service.Request(request, nil)

	return
}

// GetTablesForRole : Get virtualized tables by role
// Retrieves the list of virtualized tables that have a specific role.
func (dataVirtualization *DataVirtualizationV1) GetTablesForRole(getTablesForRoleOptions *GetTablesForRoleOptions) (result *TablesForRoleResponse, response *core.DetailedResponse, err error) {
	return dataVirtualization.GetTablesForRoleWithContext(context.Background(), getTablesForRoleOptions)
}

// GetTablesForRoleWithContext is an alternate form of the GetTablesForRole method which supports a Context parameter
func (dataVirtualization *DataVirtualizationV1) GetTablesForRoleWithContext(ctx context.Context, getTablesForRoleOptions *GetTablesForRoleOptions) (result *TablesForRoleResponse, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(getTablesForRoleOptions, "getTablesForRoleOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(getTablesForRoleOptions, "getTablesForRoleOptions")
	if err != nil {
		return
	}

	pathParamsMap := map[string]string{
		"rolename": *getTablesForRoleOptions.Rolename,
	}

	builder := core.NewRequestBuilder(core.GET)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = dataVirtualization.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(dataVirtualization.Service.Options.URL, `/v2/privileges/tables/role/{rolename}`, pathParamsMap)
	if err != nil {
		return
	}

	for headerName, headerValue := range getTablesForRoleOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("data_virtualization", "V1", "GetTablesForRole")
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
	err = core.UnmarshalModel(rawResponse, "", &result, UnmarshalTablesForRoleResponse)
	if err != nil {
		return
	}
	response.Result = result

	return
}

// VirtualizeTableV2 : Virtualize table
// Transforms a given data source table into a virtualized table.
func (dataVirtualization *DataVirtualizationV1) VirtualizeTableV2(virtualizeTableV2Options *VirtualizeTableV2Options) (result *VirtualizeTableResponse, response *core.DetailedResponse, err error) {
	return dataVirtualization.VirtualizeTableV2WithContext(context.Background(), virtualizeTableV2Options)
}

// VirtualizeTableV2WithContext is an alternate form of the VirtualizeTableV2 method which supports a Context parameter
func (dataVirtualization *DataVirtualizationV1) VirtualizeTableV2WithContext(ctx context.Context, virtualizeTableV2Options *VirtualizeTableV2Options) (result *VirtualizeTableResponse, response *core.DetailedResponse, err error) {
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
	err = core.UnmarshalModel(rawResponse, "", &result, UnmarshalVirtualizeTableResponse)
	if err != nil {
		return
	}
	response.Result = result

	return
}

// DeleteTable : Delete virtualized table
// Removes the specified virtualized table. You must specify the schema and table name.
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
		"table_name": *deleteTableOptions.TableName,
	}

	builder := core.NewRequestBuilder(core.DELETE)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = dataVirtualization.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(dataVirtualization.Service.Options.URL, `/v2/mydata/tables/{table_name}`, pathParamsMap)
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

	Properties *PostDatasourceConnectionParametersProperties `json:"properties" validate:"required"`

	AssetCategory *string `json:"asset_category,omitempty"`

	// Allows users to set headers on API requests
	Headers map[string]string
}

// NewAddDatasourceConnectionOptions : Instantiate AddDatasourceConnectionOptions
func (*DataVirtualizationV1) NewAddDatasourceConnectionOptions(datasourceType string, name string, originCountry string, properties *PostDatasourceConnectionParametersProperties) *AddDatasourceConnectionOptions {
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
func (options *AddDatasourceConnectionOptions) SetProperties(properties *PostDatasourceConnectionParametersProperties) *AddDatasourceConnectionOptions {
	options.Properties = properties
	return options
}

// SetAssetCategory : Allow user to set AssetCategory
func (options *AddDatasourceConnectionOptions) SetAssetCategory(assetCategory string) *AddDatasourceConnectionOptions {
	options.AssetCategory = core.StringPtr(assetCategory)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *AddDatasourceConnectionOptions) SetHeaders(param map[string]string) *AddDatasourceConnectionOptions {
	options.Headers = param
	return options
}

// DatasourceNodesResponseV2DatasourceNodesArrayItem : DatasourceNodesResponseV2DatasourceNodesArrayItem struct
type DatasourceNodesResponseV2DatasourceNodesArrayItem struct {
	// The name of the node that a datasource connection associates.
	NodeName *string `json:"node_name,omitempty"`

	// The description of the node that a datasource connection associates.
	NodeDescription *string `json:"node_description,omitempty"`

	// The type of connector, for example, H stands for Hosted, ie running within the cluster, F means Fenced Mode Process,
	// ie direct within Data Virtualization instance.
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
	// Specifies the data source connection to be deleted.
	Cid *string `json:"cid" validate:"required"`

	// Specifies the data source connection to be deleted.
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
	// The schema of virtualized table to be deleted.
	SchemaName *string `json:"schema_name" validate:"required"`

	// The name of virtualized table to be deleted.
	TableName *string `json:"table_name" validate:"required,ne="`

	// Allows users to set headers on API requests
	Headers map[string]string
}

// NewDeleteTableOptions : Instantiate DeleteTableOptions
func (*DataVirtualizationV1) NewDeleteTableOptions(schemaName string, tableName string) *DeleteTableOptions {
	return &DeleteTableOptions{
		SchemaName: core.StringPtr(schemaName),
		TableName: core.StringPtr(tableName),
	}
}

// SetSchemaName : Allow user to set SchemaName
func (options *DeleteTableOptions) SetSchemaName(schemaName string) *DeleteTableOptions {
	options.SchemaName = core.StringPtr(schemaName)
	return options
}

// SetTableName : Allow user to set TableName
func (options *DeleteTableOptions) SetTableName(tableName string) *DeleteTableOptions {
	options.TableName = core.StringPtr(tableName)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *DeleteTableOptions) SetHeaders(param map[string]string) *DeleteTableOptions {
	options.Headers = param
	return options
}

// GetDatasourceConnectionsOptions : The GetDatasourceConnections options.
type GetDatasourceConnectionsOptions struct {

	// Allows users to set headers on API requests
	Headers map[string]string
}

// NewGetDatasourceConnectionsOptions : Instantiate GetDatasourceConnectionsOptions
func (*DataVirtualizationV1) NewGetDatasourceConnectionsOptions() *GetDatasourceConnectionsOptions {
	return &GetDatasourceConnectionsOptions{}
}

// SetHeaders : Allow user to set Headers
func (options *GetDatasourceConnectionsOptions) SetHeaders(param map[string]string) *GetDatasourceConnectionsOptions {
	options.Headers = param
	return options
}

// GetTablesForRoleOptions : The GetTablesForRole options.
type GetTablesForRoleOptions struct {
	// Data Virtualization has four roles: ADMIN, STEWARD, ENGINEER and USER The value of rolename should be one of them.
	Rolename *string `json:"rolename" validate:"required,ne="`

	// Allows users to set headers on API requests
	Headers map[string]string
}

// NewGetTablesForRoleOptions : Instantiate GetTablesForRoleOptions
func (*DataVirtualizationV1) NewGetTablesForRoleOptions(rolename string) *GetTablesForRoleOptions {
	return &GetTablesForRoleOptions{
		Rolename: core.StringPtr(rolename),
	}
}

// SetRolename : Allow user to set Rolename
func (options *GetTablesForRoleOptions) SetRolename(rolename string) *GetTablesForRoleOptions {
	options.Rolename = core.StringPtr(rolename)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *GetTablesForRoleOptions) SetHeaders(param map[string]string) *GetTablesForRoleOptions {
	options.Headers = param
	return options
}

// GrantRolesToVirtualizedTableOptions : The GrantRolesToVirtualizedTable options.
type GrantRolesToVirtualizedTableOptions struct {
	Body []PostRolePrivilegesParametersBodyItem `json:"body,omitempty"`

	// Allows users to set headers on API requests
	Headers map[string]string
}

// NewGrantRolesToVirtualizedTableOptions : Instantiate GrantRolesToVirtualizedTableOptions
func (*DataVirtualizationV1) NewGrantRolesToVirtualizedTableOptions() *GrantRolesToVirtualizedTableOptions {
	return &GrantRolesToVirtualizedTableOptions{}
}

// SetBody : Allow user to set Body
func (options *GrantRolesToVirtualizedTableOptions) SetBody(body []PostRolePrivilegesParametersBodyItem) *GrantRolesToVirtualizedTableOptions {
	options.Body = body
	return options
}

// SetHeaders : Allow user to set Headers
func (options *GrantRolesToVirtualizedTableOptions) SetHeaders(param map[string]string) *GrantRolesToVirtualizedTableOptions {
	options.Headers = param
	return options
}

// GrantUserToVirtualTableOptions : The GrantUserToVirtualTable options.
type GrantUserToVirtualTableOptions struct {
	Body []PostUserPrivilegesParametersBodyItem `json:"body,omitempty"`

	// Allows users to set headers on API requests
	Headers map[string]string
}

// NewGrantUserToVirtualTableOptions : Instantiate GrantUserToVirtualTableOptions
func (*DataVirtualizationV1) NewGrantUserToVirtualTableOptions() *GrantUserToVirtualTableOptions {
	return &GrantUserToVirtualTableOptions{}
}

// SetBody : Allow user to set Body
func (options *GrantUserToVirtualTableOptions) SetBody(body []PostUserPrivilegesParametersBodyItem) *GrantUserToVirtualTableOptions {
	options.Body = body
	return options
}

// SetHeaders : Allow user to set Headers
func (options *GrantUserToVirtualTableOptions) SetHeaders(param map[string]string) *GrantUserToVirtualTableOptions {
	options.Headers = param
	return options
}

// PostDatasourceConnectionParametersProperties : PostDatasourceConnectionParametersProperties struct
type PostDatasourceConnectionParametersProperties struct {
	AccessToken *string `json:"access_token,omitempty"`

	AccountName *string `json:"account_name,omitempty"`

	ApiKey *string `json:"api_key,omitempty"`

	AuthType *string `json:"auth_type,omitempty"`

	ClientID *string `json:"client_id,omitempty"`

	ClientSecret *string `json:"client_secret,omitempty"`

	Collection *string `json:"collection,omitempty"`

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

	Role *string `json:"role,omitempty"`

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


// UnmarshalPostDatasourceConnectionParametersProperties unmarshals an instance of PostDatasourceConnectionParametersProperties from the specified map of raw messages.
func UnmarshalPostDatasourceConnectionParametersProperties(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(PostDatasourceConnectionParametersProperties)
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
	err = core.UnmarshalPrimitive(m, "collection", &obj.Collection)
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
	err = core.UnmarshalPrimitive(m, "role", &obj.Role)
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

// PostDatasourceConnectionResponse : PostDatasourceConnectionResponse struct
type PostDatasourceConnectionResponse struct {
	// The type of data source that you want to add.
	DatasourceType *string `json:"datasource_type" validate:"required"`

	// The name of data source.
	Name *string `json:"name" validate:"required"`
}


// UnmarshalPostDatasourceConnectionResponse unmarshals an instance of PostDatasourceConnectionResponse from the specified map of raw messages.
func UnmarshalPostDatasourceConnectionResponse(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(PostDatasourceConnectionResponse)
	err = core.UnmarshalPrimitive(m, "datasource_type", &obj.DatasourceType)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "name", &obj.Name)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// PostRolePrivilegesParametersBodyItem : PostRolePrivilegesParametersBodyItem struct
type PostRolePrivilegesParametersBodyItem struct {
	// The name of the virtualized table.
	TableName *string `json:"table_name,omitempty"`

	// The schema of the virtualized table.
	TableSchema *string `json:"table_schema,omitempty"`

	// The identifier of the authorization, if grant access to all users, the value is PUBLIC, othervise the value is the
	// data virtualization username.
	RoleToGrant *string `json:"role_to_grant,omitempty"`
}


// UnmarshalPostRolePrivilegesParametersBodyItem unmarshals an instance of PostRolePrivilegesParametersBodyItem from the specified map of raw messages.
func UnmarshalPostRolePrivilegesParametersBodyItem(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(PostRolePrivilegesParametersBodyItem)
	err = core.UnmarshalPrimitive(m, "table_name", &obj.TableName)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "table_schema", &obj.TableSchema)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "role_to_grant", &obj.RoleToGrant)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// PostUserPrivilegesParametersBodyItem : PostUserPrivilegesParametersBodyItem struct
type PostUserPrivilegesParametersBodyItem struct {
	// The name of the virtualized table.
	TableName *string `json:"table_name,omitempty"`

	// The schema of the virtualized table.
	TableSchema *string `json:"table_schema,omitempty"`

	// The identifier of the authorization, if grant access to all users, the value is PUBLIC, othervise the value is the
	// data virtualization username.
	Authid *string `json:"authid,omitempty"`
}


// UnmarshalPostUserPrivilegesParametersBodyItem unmarshals an instance of PostUserPrivilegesParametersBodyItem from the specified map of raw messages.
func UnmarshalPostUserPrivilegesParametersBodyItem(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(PostUserPrivilegesParametersBodyItem)
	err = core.UnmarshalPrimitive(m, "table_name", &obj.TableName)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "table_schema", &obj.TableSchema)
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

// RevokeRoleFromTableV2Options : The RevokeRoleFromTableV2 options.
type RevokeRoleFromTableV2Options struct {
	// The Data Virtualization role type, the value could be DV_ADMIN, DV_ENGINEER, DV_STEWARD or DV_WORKER.
	RoleToRevoke *string `json:"role_to_revoke" validate:"required"`

	// The virtualized table's name.
	TableName *string `json:"table_name" validate:"required"`

	// The virtualized table's schema name.
	TableSchema *string `json:"table_schema" validate:"required"`

	// Allows users to set headers on API requests
	Headers map[string]string
}

// NewRevokeRoleFromTableV2Options : Instantiate RevokeRoleFromTableV2Options
func (*DataVirtualizationV1) NewRevokeRoleFromTableV2Options(roleToRevoke string, tableName string, tableSchema string) *RevokeRoleFromTableV2Options {
	return &RevokeRoleFromTableV2Options{
		RoleToRevoke: core.StringPtr(roleToRevoke),
		TableName: core.StringPtr(tableName),
		TableSchema: core.StringPtr(tableSchema),
	}
}

// SetRoleToRevoke : Allow user to set RoleToRevoke
func (options *RevokeRoleFromTableV2Options) SetRoleToRevoke(roleToRevoke string) *RevokeRoleFromTableV2Options {
	options.RoleToRevoke = core.StringPtr(roleToRevoke)
	return options
}

// SetTableName : Allow user to set TableName
func (options *RevokeRoleFromTableV2Options) SetTableName(tableName string) *RevokeRoleFromTableV2Options {
	options.TableName = core.StringPtr(tableName)
	return options
}

// SetTableSchema : Allow user to set TableSchema
func (options *RevokeRoleFromTableV2Options) SetTableSchema(tableSchema string) *RevokeRoleFromTableV2Options {
	options.TableSchema = core.StringPtr(tableSchema)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *RevokeRoleFromTableV2Options) SetHeaders(param map[string]string) *RevokeRoleFromTableV2Options {
	options.Headers = param
	return options
}

// RevokeUserFromObjectOptions : The RevokeUserFromObject options.
type RevokeUserFromObjectOptions struct {
	// The Data Virtualization user name, if the value is PUBLIC, it means revoke access privilege from all Data
	// Virtualization users.
	Authid *string `json:"authid" validate:"required"`

	// The virtualized table's name.
	TableName *string `json:"table_name" validate:"required"`

	// The virtualized table's schema name.
	TableSchema *string `json:"table_schema" validate:"required"`

	// Allows users to set headers on API requests
	Headers map[string]string
}

// NewRevokeUserFromObjectOptions : Instantiate RevokeUserFromObjectOptions
func (*DataVirtualizationV1) NewRevokeUserFromObjectOptions(authid string, tableName string, tableSchema string) *RevokeUserFromObjectOptions {
	return &RevokeUserFromObjectOptions{
		Authid: core.StringPtr(authid),
		TableName: core.StringPtr(tableName),
		TableSchema: core.StringPtr(tableSchema),
	}
}

// SetAuthid : Allow user to set Authid
func (options *RevokeUserFromObjectOptions) SetAuthid(authid string) *RevokeUserFromObjectOptions {
	options.Authid = core.StringPtr(authid)
	return options
}

// SetTableName : Allow user to set TableName
func (options *RevokeUserFromObjectOptions) SetTableName(tableName string) *RevokeUserFromObjectOptions {
	options.TableName = core.StringPtr(tableName)
	return options
}

// SetTableSchema : Allow user to set TableSchema
func (options *RevokeUserFromObjectOptions) SetTableSchema(tableSchema string) *RevokeUserFromObjectOptions {
	options.TableSchema = core.StringPtr(tableSchema)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *RevokeUserFromObjectOptions) SetHeaders(param map[string]string) *RevokeUserFromObjectOptions {
	options.Headers = param
	return options
}

// TablesForRoleResponse : TablesForRoleResponse struct
type TablesForRoleResponse struct {
	Objects []TablesForRoleResponseObjectsItem `json:"objects,omitempty"`
}


// UnmarshalTablesForRoleResponse unmarshals an instance of TablesForRoleResponse from the specified map of raw messages.
func UnmarshalTablesForRoleResponse(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(TablesForRoleResponse)
	err = core.UnmarshalModel(m, "objects", &obj.Objects, UnmarshalTablesForRoleResponseObjectsItem)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// TablesForRoleResponseObjectsItem : TablesForRoleResponseObjectsItem struct
type TablesForRoleResponseObjectsItem struct {
	// The virtualized table name that is granted access to role ROLENAME.
	TableName *string `json:"table_name,omitempty"`

	// The SCHEMA of virtualized table that is granted access to role ROLENAME.
	TableSchema *string `json:"table_schema,omitempty"`
}


// UnmarshalTablesForRoleResponseObjectsItem unmarshals an instance of TablesForRoleResponseObjectsItem from the specified map of raw messages.
func UnmarshalTablesForRoleResponseObjectsItem(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(TablesForRoleResponseObjectsItem)
	err = core.UnmarshalPrimitive(m, "table_name", &obj.TableName)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "table_schema", &obj.TableSchema)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// VirtualizeTableParameterSourceTableDefItem : VirtualizeTableParameterSourceTableDefItem struct
type VirtualizeTableParameterSourceTableDefItem struct {
	// The name of the column.
	ColumnName *string `json:"column_name" validate:"required"`

	// The type of the column.
	ColumnType *string `json:"column_type" validate:"required"`
}


// NewVirtualizeTableParameterSourceTableDefItem : Instantiate VirtualizeTableParameterSourceTableDefItem (Generic Model Constructor)
func (*DataVirtualizationV1) NewVirtualizeTableParameterSourceTableDefItem(columnName string, columnType string) (model *VirtualizeTableParameterSourceTableDefItem, err error) {
	model = &VirtualizeTableParameterSourceTableDefItem{
		ColumnName: core.StringPtr(columnName),
		ColumnType: core.StringPtr(columnType),
	}
	err = core.ValidateStruct(model, "required parameters")
	return
}

// UnmarshalVirtualizeTableParameterSourceTableDefItem unmarshals an instance of VirtualizeTableParameterSourceTableDefItem from the specified map of raw messages.
func UnmarshalVirtualizeTableParameterSourceTableDefItem(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(VirtualizeTableParameterSourceTableDefItem)
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

// VirtualizeTableParameterVirtualTableDefItem : VirtualizeTableParameterVirtualTableDefItem struct
type VirtualizeTableParameterVirtualTableDefItem struct {
	// The name of the column.
	ColumnName *string `json:"column_name" validate:"required"`

	// The type of the column.
	ColumnType *string `json:"column_type" validate:"required"`
}


// NewVirtualizeTableParameterVirtualTableDefItem : Instantiate VirtualizeTableParameterVirtualTableDefItem (Generic Model Constructor)
func (*DataVirtualizationV1) NewVirtualizeTableParameterVirtualTableDefItem(columnName string, columnType string) (model *VirtualizeTableParameterVirtualTableDefItem, err error) {
	model = &VirtualizeTableParameterVirtualTableDefItem{
		ColumnName: core.StringPtr(columnName),
		ColumnType: core.StringPtr(columnType),
	}
	err = core.ValidateStruct(model, "required parameters")
	return
}

// UnmarshalVirtualizeTableParameterVirtualTableDefItem unmarshals an instance of VirtualizeTableParameterVirtualTableDefItem from the specified map of raw messages.
func UnmarshalVirtualizeTableParameterVirtualTableDefItem(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(VirtualizeTableParameterVirtualTableDefItem)
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

// VirtualizeTableResponse : VirtualizeTableResponse struct
type VirtualizeTableResponse struct {
	// The name of the source table.
	SourceName *string `json:"source_name" validate:"required"`

	// The name of the table that will be virtualized.
	VirtualName *string `json:"virtual_name" validate:"required"`

	// The schema of the table that will be virtualized.
	VirtualSchema *string `json:"virtual_schema" validate:"required"`
}


// UnmarshalVirtualizeTableResponse unmarshals an instance of VirtualizeTableResponse from the specified map of raw messages.
func UnmarshalVirtualizeTableResponse(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(VirtualizeTableResponse)
	err = core.UnmarshalPrimitive(m, "source_name", &obj.SourceName)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "virtual_name", &obj.VirtualName)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "virtual_schema", &obj.VirtualSchema)
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

	SourceTableDef []VirtualizeTableParameterSourceTableDefItem `json:"source_table_def" validate:"required"`

	Sources []string `json:"sources" validate:"required"`

	// The name of the table that will be virtualized.
	VirtualName *string `json:"virtual_name" validate:"required"`

	// The schema of the table that will be virtualized.
	VirtualSchema *string `json:"virtual_schema" validate:"required"`

	VirtualTableDef []VirtualizeTableParameterVirtualTableDefItem `json:"virtual_table_def" validate:"required"`

	// The columns that are included in the source table.
	IsIncludedColumns *string `json:"is_included_columns,omitempty"`

	// Determines whether to replace columns in the virtualized table.
	Replace *bool `json:"replace,omitempty"`

	// Allows users to set headers on API requests
	Headers map[string]string
}

// NewVirtualizeTableV2Options : Instantiate VirtualizeTableV2Options
func (*DataVirtualizationV1) NewVirtualizeTableV2Options(sourceName string, sourceTableDef []VirtualizeTableParameterSourceTableDefItem, sources []string, virtualName string, virtualSchema string, virtualTableDef []VirtualizeTableParameterVirtualTableDefItem) *VirtualizeTableV2Options {
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
func (options *VirtualizeTableV2Options) SetSourceTableDef(sourceTableDef []VirtualizeTableParameterSourceTableDefItem) *VirtualizeTableV2Options {
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
func (options *VirtualizeTableV2Options) SetVirtualTableDef(virtualTableDef []VirtualizeTableParameterVirtualTableDefItem) *VirtualizeTableV2Options {
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
