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
 * IBM OpenAPI SDK Code Generator Version: 3.34.1-ad041667-20210617-195430
 */

// Package datavirtualizationv1 : Operations and models for the DataVirtualizationV1 service
package datavirtualizationv1

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"time"

	common "github.com/IBM/data-virtualization-on-cloud-go-sdk/common"
	"github.com/IBM/go-sdk-core/v5/core"
)

// DataVirtualizationV1 : The Data Virtualization REST API connects to your service, so you can manage your virtual
// data, data sources, and user roles.
//
// Version: 1.6.0
type DataVirtualizationV1 struct {
	Service *core.BaseService
}

// DefaultServiceName is the default key used to find external configuration information.
const DefaultServiceName = "data_virtualization"

// DataVirtualizationV1Options : Service options
type DataVirtualizationV1Options struct {
	ServiceName   string
	URL           string
	Authenticator core.Authenticator
}

// NewDataVirtualizationV1UsingExternalConfig : constructs an instance of DataVirtualizationV1 with passed in options and external configuration.
func NewDataVirtualizationV1UsingExternalConfig(options *DataVirtualizationV1Options) (dataVirtualization *DataVirtualizationV1, err error) {
	if options.ServiceName == "" {
		options.ServiceName = DefaultServiceName
	}

	if options.Authenticator == nil {
		options.Authenticator, err = core.GetAuthenticatorFromEnvironment(options.ServiceName)
		if err != nil {
			return
		}
	}

	dataVirtualization, err = NewDataVirtualizationV1(options)
	if err != nil {
		return
	}

	err = dataVirtualization.Service.ConfigureService(options.ServiceName)
	if err != nil {
		return
	}

	if options.URL != "" {
		err = dataVirtualization.Service.SetServiceURL(options.URL)
	}
	return
}

// NewDataVirtualizationV1 : constructs an instance of DataVirtualizationV1 with passed in options.
func NewDataVirtualizationV1(options *DataVirtualizationV1Options) (service *DataVirtualizationV1, err error) {
	serviceOptions := &core.ServiceOptions{
		Authenticator: options.Authenticator,
	}

	baseService, err := core.NewBaseService(serviceOptions)
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

// GetServiceURLForRegion returns the service URL to be used for the specified region
func GetServiceURLForRegion(region string) (string, error) {
	return "", fmt.Errorf("service does not support regional URLs")
}

// Clone makes a copy of "dataVirtualization" suitable for processing requests.
func (dataVirtualization *DataVirtualizationV1) Clone() *DataVirtualizationV1 {
	if core.IsNil(dataVirtualization) {
		return nil
	}
	clone := *dataVirtualization
	clone.Service = dataVirtualization.Service.Clone()
	return &clone
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

// ListDatasourceConnections : Get data source connections
// Gets all data source connections that are connected to the service.
func (dataVirtualization *DataVirtualizationV1) ListDatasourceConnections(listDatasourceConnectionsOptions *ListDatasourceConnectionsOptions) (result *DatasourceConnectionsList, response *core.DetailedResponse, err error) {
	return dataVirtualization.ListDatasourceConnectionsWithContext(context.Background(), listDatasourceConnectionsOptions)
}

// ListDatasourceConnectionsWithContext is an alternate form of the ListDatasourceConnections method which supports a Context parameter
func (dataVirtualization *DataVirtualizationV1) ListDatasourceConnectionsWithContext(ctx context.Context, listDatasourceConnectionsOptions *ListDatasourceConnectionsOptions) (result *DatasourceConnectionsList, response *core.DetailedResponse, err error) {
	err = core.ValidateStruct(listDatasourceConnectionsOptions, "listDatasourceConnectionsOptions")
	if err != nil {
		return
	}

	builder := core.NewRequestBuilder(core.GET)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = dataVirtualization.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(dataVirtualization.Service.Options.URL, `/v2/datasource/connections`, nil)
	if err != nil {
		return
	}

	for headerName, headerValue := range listDatasourceConnectionsOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("data_virtualization", "V1", "ListDatasourceConnections")
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
	if rawResponse != nil {
		err = core.UnmarshalModel(rawResponse, "", &result, UnmarshalDatasourceConnectionsList)
		if err != nil {
			return
		}
		response.Result = result
	}

	return
}

// AddDatasourceConnection : Add data source connection
// Adds a data source connection to the Data Virtualization service.
func (dataVirtualization *DataVirtualizationV1) AddDatasourceConnection(addDatasourceConnectionOptions *AddDatasourceConnectionOptions) (result *PostDatasourceConnection, response *core.DetailedResponse, err error) {
	return dataVirtualization.AddDatasourceConnectionWithContext(context.Background(), addDatasourceConnectionOptions)
}

// AddDatasourceConnectionWithContext is an alternate form of the AddDatasourceConnection method which supports a Context parameter
func (dataVirtualization *DataVirtualizationV1) AddDatasourceConnectionWithContext(ctx context.Context, addDatasourceConnectionOptions *AddDatasourceConnectionOptions) (result *PostDatasourceConnection, response *core.DetailedResponse, err error) {
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
	_, err = builder.ResolveRequestURL(dataVirtualization.Service.Options.URL, `/v2/datasource/connections`, nil)
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
	if rawResponse != nil {
		err = core.UnmarshalModel(rawResponse, "", &result, UnmarshalPostDatasourceConnection)
		if err != nil {
			return
		}
		response.Result = result
	}

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

	pathParamsMap := map[string]string{
		"connection_id": *deleteDatasourceConnectionOptions.ConnectionID,
	}

	builder := core.NewRequestBuilder(core.DELETE)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = dataVirtualization.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(dataVirtualization.Service.Options.URL, `/v2/datasource/connections/{connection_id}`, pathParamsMap)
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

	if deleteDatasourceConnectionOptions.Cid != nil {
		builder.AddQuery("cid", fmt.Sprint(*deleteDatasourceConnectionOptions.Cid))
	}

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
	if grantUserToVirtualTableOptions.TableName != nil {
		body["table_name"] = grantUserToVirtualTableOptions.TableName
	}
	if grantUserToVirtualTableOptions.TableSchema != nil {
		body["table_schema"] = grantUserToVirtualTableOptions.TableSchema
	}
	if grantUserToVirtualTableOptions.Authid != nil {
		body["authid"] = grantUserToVirtualTableOptions.Authid
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

	pathParamsMap := map[string]string{
		"authid": *revokeUserFromObjectOptions.Authid,
	}

	builder := core.NewRequestBuilder(core.DELETE)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = dataVirtualization.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(dataVirtualization.Service.Options.URL, `/v2/privileges/users/{authid}`, pathParamsMap)
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
	if grantRolesToVirtualizedTableOptions.TableName != nil {
		body["table_name"] = grantRolesToVirtualizedTableOptions.TableName
	}
	if grantRolesToVirtualizedTableOptions.TableSchema != nil {
		body["table_schema"] = grantRolesToVirtualizedTableOptions.TableSchema
	}
	if grantRolesToVirtualizedTableOptions.RoleName != nil {
		body["role_name"] = grantRolesToVirtualizedTableOptions.RoleName
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

// DvaasRevokeRoleFromTable : Delete role
// Revokes roles for a virtualized table.
func (dataVirtualization *DataVirtualizationV1) DvaasRevokeRoleFromTable(dvaasRevokeRoleFromTableOptions *DvaasRevokeRoleFromTableOptions) (response *core.DetailedResponse, err error) {
	return dataVirtualization.DvaasRevokeRoleFromTableWithContext(context.Background(), dvaasRevokeRoleFromTableOptions)
}

// DvaasRevokeRoleFromTableWithContext is an alternate form of the DvaasRevokeRoleFromTable method which supports a Context parameter
func (dataVirtualization *DataVirtualizationV1) DvaasRevokeRoleFromTableWithContext(ctx context.Context, dvaasRevokeRoleFromTableOptions *DvaasRevokeRoleFromTableOptions) (response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(dvaasRevokeRoleFromTableOptions, "dvaasRevokeRoleFromTableOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(dvaasRevokeRoleFromTableOptions, "dvaasRevokeRoleFromTableOptions")
	if err != nil {
		return
	}

	pathParamsMap := map[string]string{
		"role_name": *dvaasRevokeRoleFromTableOptions.RoleName,
	}

	builder := core.NewRequestBuilder(core.DELETE)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = dataVirtualization.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(dataVirtualization.Service.Options.URL, `/v2/privileges/roles/{role_name}`, pathParamsMap)
	if err != nil {
		return
	}

	for headerName, headerValue := range dvaasRevokeRoleFromTableOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("data_virtualization", "V1", "DvaasRevokeRoleFromTable")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddQuery("table_name", fmt.Sprint(*dvaasRevokeRoleFromTableOptions.TableName))
	builder.AddQuery("table_schema", fmt.Sprint(*dvaasRevokeRoleFromTableOptions.TableSchema))

	request, err := builder.Build()
	if err != nil {
		return
	}

	response, err = dataVirtualization.Service.Request(request, nil)

	return
}

// ListTablesForRole : Get virtualized tables by role
// Retrieves the list of virtualized tables that have a specific role.
func (dataVirtualization *DataVirtualizationV1) ListTablesForRole(listTablesForRoleOptions *ListTablesForRoleOptions) (result *TablesForRoleResponse, response *core.DetailedResponse, err error) {
	return dataVirtualization.ListTablesForRoleWithContext(context.Background(), listTablesForRoleOptions)
}

// ListTablesForRoleWithContext is an alternate form of the ListTablesForRole method which supports a Context parameter
func (dataVirtualization *DataVirtualizationV1) ListTablesForRoleWithContext(ctx context.Context, listTablesForRoleOptions *ListTablesForRoleOptions) (result *TablesForRoleResponse, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(listTablesForRoleOptions, "listTablesForRoleOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(listTablesForRoleOptions, "listTablesForRoleOptions")
	if err != nil {
		return
	}

	builder := core.NewRequestBuilder(core.GET)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = dataVirtualization.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(dataVirtualization.Service.Options.URL, `/v2/privileges/tables`, nil)
	if err != nil {
		return
	}

	for headerName, headerValue := range listTablesForRoleOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("data_virtualization", "V1", "ListTablesForRole")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}
	builder.AddHeader("Accept", "application/json")

	builder.AddQuery("rolename", fmt.Sprint(*listTablesForRoleOptions.Rolename))

	request, err := builder.Build()
	if err != nil {
		return
	}

	var rawResponse map[string]json.RawMessage
	response, err = dataVirtualization.Service.Request(request, &rawResponse)
	if err != nil {
		return
	}
	if rawResponse != nil {
		err = core.UnmarshalModel(rawResponse, "", &result, UnmarshalTablesForRoleResponse)
		if err != nil {
			return
		}
		response.Result = result
	}

	return
}

// TurnOnPolicyV2 : Turn on or off WKC policy enforcement status
// Turn on WKC policy enforcement status.
func (dataVirtualization *DataVirtualizationV1) TurnOnPolicyV2(turnOnPolicyV2Options *TurnOnPolicyV2Options) (result *TurnOnPolicyV2Response, response *core.DetailedResponse, err error) {
	return dataVirtualization.TurnOnPolicyV2WithContext(context.Background(), turnOnPolicyV2Options)
}

// TurnOnPolicyV2WithContext is an alternate form of the TurnOnPolicyV2 method which supports a Context parameter
func (dataVirtualization *DataVirtualizationV1) TurnOnPolicyV2WithContext(ctx context.Context, turnOnPolicyV2Options *TurnOnPolicyV2Options) (result *TurnOnPolicyV2Response, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(turnOnPolicyV2Options, "turnOnPolicyV2Options cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(turnOnPolicyV2Options, "turnOnPolicyV2Options")
	if err != nil {
		return
	}

	builder := core.NewRequestBuilder(core.PUT)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = dataVirtualization.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(dataVirtualization.Service.Options.URL, `/v2/security/policy/status`, nil)
	if err != nil {
		return
	}

	for headerName, headerValue := range turnOnPolicyV2Options.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("data_virtualization", "V1", "TurnOnPolicyV2")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}
	builder.AddHeader("Accept", "application/json")

	builder.AddQuery("status", fmt.Sprint(*turnOnPolicyV2Options.Status))

	request, err := builder.Build()
	if err != nil {
		return
	}

	var rawResponse map[string]json.RawMessage
	response, err = dataVirtualization.Service.Request(request, &rawResponse)
	if err != nil {
		return
	}
	if rawResponse != nil {
		err = core.UnmarshalModel(rawResponse, "", &result, UnmarshalTurnOnPolicyV2Response)
		if err != nil {
			return
		}
		response.Result = result
	}

	return
}

// CheckPolicyStatusV2 : Get WKC policy enforcement status
// Get WKC policy enforcement status, return enabled or disabled.
func (dataVirtualization *DataVirtualizationV1) CheckPolicyStatusV2(checkPolicyStatusV2Options *CheckPolicyStatusV2Options) (result *CheckPolicyStatusV2Response, response *core.DetailedResponse, err error) {
	return dataVirtualization.CheckPolicyStatusV2WithContext(context.Background(), checkPolicyStatusV2Options)
}

// CheckPolicyStatusV2WithContext is an alternate form of the CheckPolicyStatusV2 method which supports a Context parameter
func (dataVirtualization *DataVirtualizationV1) CheckPolicyStatusV2WithContext(ctx context.Context, checkPolicyStatusV2Options *CheckPolicyStatusV2Options) (result *CheckPolicyStatusV2Response, response *core.DetailedResponse, err error) {
	err = core.ValidateStruct(checkPolicyStatusV2Options, "checkPolicyStatusV2Options")
	if err != nil {
		return
	}

	builder := core.NewRequestBuilder(core.GET)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = dataVirtualization.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(dataVirtualization.Service.Options.URL, `/v2/security/policy/status`, nil)
	if err != nil {
		return
	}

	for headerName, headerValue := range checkPolicyStatusV2Options.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("data_virtualization", "V1", "CheckPolicyStatusV2")
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
	if rawResponse != nil {
		err = core.UnmarshalModel(rawResponse, "", &result, UnmarshalCheckPolicyStatusV2Response)
		if err != nil {
			return
		}
		response.Result = result
	}

	return
}

// DvaasVirtualizeTable : Virtualize table
// Transforms a given data source table into a virtualized table.
func (dataVirtualization *DataVirtualizationV1) DvaasVirtualizeTable(dvaasVirtualizeTableOptions *DvaasVirtualizeTableOptions) (result *VirtualizeTableResponse, response *core.DetailedResponse, err error) {
	return dataVirtualization.DvaasVirtualizeTableWithContext(context.Background(), dvaasVirtualizeTableOptions)
}

// DvaasVirtualizeTableWithContext is an alternate form of the DvaasVirtualizeTable method which supports a Context parameter
func (dataVirtualization *DataVirtualizationV1) DvaasVirtualizeTableWithContext(ctx context.Context, dvaasVirtualizeTableOptions *DvaasVirtualizeTableOptions) (result *VirtualizeTableResponse, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(dvaasVirtualizeTableOptions, "dvaasVirtualizeTableOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(dvaasVirtualizeTableOptions, "dvaasVirtualizeTableOptions")
	if err != nil {
		return
	}

	builder := core.NewRequestBuilder(core.POST)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = dataVirtualization.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(dataVirtualization.Service.Options.URL, `/v2/virtualization/tables`, nil)
	if err != nil {
		return
	}

	for headerName, headerValue := range dvaasVirtualizeTableOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("data_virtualization", "V1", "DvaasVirtualizeTable")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}
	builder.AddHeader("Accept", "application/json")
	builder.AddHeader("Content-Type", "application/json")

	body := make(map[string]interface{})
	if dvaasVirtualizeTableOptions.SourceName != nil {
		body["source_name"] = dvaasVirtualizeTableOptions.SourceName
	}
	if dvaasVirtualizeTableOptions.SourceTableDef != nil {
		body["source_table_def"] = dvaasVirtualizeTableOptions.SourceTableDef
	}
	if dvaasVirtualizeTableOptions.Sources != nil {
		body["sources"] = dvaasVirtualizeTableOptions.Sources
	}
	if dvaasVirtualizeTableOptions.VirtualName != nil {
		body["virtual_name"] = dvaasVirtualizeTableOptions.VirtualName
	}
	if dvaasVirtualizeTableOptions.VirtualSchema != nil {
		body["virtual_schema"] = dvaasVirtualizeTableOptions.VirtualSchema
	}
	if dvaasVirtualizeTableOptions.VirtualTableDef != nil {
		body["virtual_table_def"] = dvaasVirtualizeTableOptions.VirtualTableDef
	}
	if dvaasVirtualizeTableOptions.IsIncludedColumns != nil {
		body["is_included_columns"] = dvaasVirtualizeTableOptions.IsIncludedColumns
	}
	if dvaasVirtualizeTableOptions.Replace != nil {
		body["replace"] = dvaasVirtualizeTableOptions.Replace
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
	if rawResponse != nil {
		err = core.UnmarshalModel(rawResponse, "", &result, UnmarshalVirtualizeTableResponse)
		if err != nil {
			return
		}
		response.Result = result
	}

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
		"virtual_name": *deleteTableOptions.VirtualName,
	}

	builder := core.NewRequestBuilder(core.DELETE)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = dataVirtualization.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(dataVirtualization.Service.Options.URL, `/v2/virtualization/tables/{virtual_name}`, pathParamsMap)
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

	builder.AddQuery("virtual_schema", fmt.Sprint(*deleteTableOptions.VirtualSchema))

	request, err := builder.Build()
	if err != nil {
		return
	}

	response, err = dataVirtualization.Service.Request(request, nil)

	return
}

// GetPrimaryCatalog : Get primary catalog ID
// Get primary catalog ID from the table DVSYS.INSTANCE_INFO.
func (dataVirtualization *DataVirtualizationV1) GetPrimaryCatalog(getPrimaryCatalogOptions *GetPrimaryCatalogOptions) (result *PrimaryCatalogInfo, response *core.DetailedResponse, err error) {
	return dataVirtualization.GetPrimaryCatalogWithContext(context.Background(), getPrimaryCatalogOptions)
}

// GetPrimaryCatalogWithContext is an alternate form of the GetPrimaryCatalog method which supports a Context parameter
func (dataVirtualization *DataVirtualizationV1) GetPrimaryCatalogWithContext(ctx context.Context, getPrimaryCatalogOptions *GetPrimaryCatalogOptions) (result *PrimaryCatalogInfo, response *core.DetailedResponse, err error) {
	err = core.ValidateStruct(getPrimaryCatalogOptions, "getPrimaryCatalogOptions")
	if err != nil {
		return
	}

	builder := core.NewRequestBuilder(core.GET)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = dataVirtualization.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(dataVirtualization.Service.Options.URL, `/v2/catalog/primary`, nil)
	if err != nil {
		return
	}

	for headerName, headerValue := range getPrimaryCatalogOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("data_virtualization", "V1", "GetPrimaryCatalog")
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
	if rawResponse != nil {
		err = core.UnmarshalModel(rawResponse, "", &result, UnmarshalPrimaryCatalogInfo)
		if err != nil {
			return
		}
		response.Result = result
	}

	return
}

// PostPrimaryCatalog : Add primary catalog
// Insert primary catalog ID into table DVSYS.INSTANCE_INFO.
func (dataVirtualization *DataVirtualizationV1) PostPrimaryCatalog(postPrimaryCatalogOptions *PostPrimaryCatalogOptions) (result *PostPrimaryCatalog, response *core.DetailedResponse, err error) {
	return dataVirtualization.PostPrimaryCatalogWithContext(context.Background(), postPrimaryCatalogOptions)
}

// PostPrimaryCatalogWithContext is an alternate form of the PostPrimaryCatalog method which supports a Context parameter
func (dataVirtualization *DataVirtualizationV1) PostPrimaryCatalogWithContext(ctx context.Context, postPrimaryCatalogOptions *PostPrimaryCatalogOptions) (result *PostPrimaryCatalog, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(postPrimaryCatalogOptions, "postPrimaryCatalogOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(postPrimaryCatalogOptions, "postPrimaryCatalogOptions")
	if err != nil {
		return
	}

	builder := core.NewRequestBuilder(core.POST)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = dataVirtualization.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(dataVirtualization.Service.Options.URL, `/v2/catalog/primary`, nil)
	if err != nil {
		return
	}

	for headerName, headerValue := range postPrimaryCatalogOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("data_virtualization", "V1", "PostPrimaryCatalog")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}
	builder.AddHeader("Accept", "application/json")
	builder.AddHeader("Content-Type", "application/json")

	body := make(map[string]interface{})
	if postPrimaryCatalogOptions.GUID != nil {
		body["guid"] = postPrimaryCatalogOptions.GUID
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
	if rawResponse != nil {
		err = core.UnmarshalModel(rawResponse, "", &result, UnmarshalPostPrimaryCatalog)
		if err != nil {
			return
		}
		response.Result = result
	}

	return
}

// DeletePrimaryCatalog : Delete primary catalog
// Delete primary catalog item in the DVSYS.INSTANCE_INFO table.
func (dataVirtualization *DataVirtualizationV1) DeletePrimaryCatalog(deletePrimaryCatalogOptions *DeletePrimaryCatalogOptions) (response *core.DetailedResponse, err error) {
	return dataVirtualization.DeletePrimaryCatalogWithContext(context.Background(), deletePrimaryCatalogOptions)
}

// DeletePrimaryCatalogWithContext is an alternate form of the DeletePrimaryCatalog method which supports a Context parameter
func (dataVirtualization *DataVirtualizationV1) DeletePrimaryCatalogWithContext(ctx context.Context, deletePrimaryCatalogOptions *DeletePrimaryCatalogOptions) (response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(deletePrimaryCatalogOptions, "deletePrimaryCatalogOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(deletePrimaryCatalogOptions, "deletePrimaryCatalogOptions")
	if err != nil {
		return
	}

	builder := core.NewRequestBuilder(core.DELETE)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = dataVirtualization.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(dataVirtualization.Service.Options.URL, `/v2/catalog/primary`, nil)
	if err != nil {
		return
	}

	for headerName, headerValue := range deletePrimaryCatalogOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("data_virtualization", "V1", "DeletePrimaryCatalog")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddQuery("guid", fmt.Sprint(*deletePrimaryCatalogOptions.GUID))

	request, err := builder.Build()
	if err != nil {
		return
	}

	response, err = dataVirtualization.Service.Request(request, nil)

	return
}

// PublishAssets : publish virtual table to WKC
// publish virtual tables to WKC.
func (dataVirtualization *DataVirtualizationV1) PublishAssets(publishAssetsOptions *PublishAssetsOptions) (result *CatalogPublishResponse, response *core.DetailedResponse, err error) {
	return dataVirtualization.PublishAssetsWithContext(context.Background(), publishAssetsOptions)
}

// PublishAssetsWithContext is an alternate form of the PublishAssets method which supports a Context parameter
func (dataVirtualization *DataVirtualizationV1) PublishAssetsWithContext(ctx context.Context, publishAssetsOptions *PublishAssetsOptions) (result *CatalogPublishResponse, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(publishAssetsOptions, "publishAssetsOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(publishAssetsOptions, "publishAssetsOptions")
	if err != nil {
		return
	}

	builder := core.NewRequestBuilder(core.POST)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = dataVirtualization.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(dataVirtualization.Service.Options.URL, `/v2/integration/catalog/publish`, nil)
	if err != nil {
		return
	}

	for headerName, headerValue := range publishAssetsOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("data_virtualization", "V1", "PublishAssets")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}
	builder.AddHeader("Accept", "application/json")
	builder.AddHeader("Content-Type", "application/json")

	body := make(map[string]interface{})
	if publishAssetsOptions.CatalogID != nil {
		body["catalog_id"] = publishAssetsOptions.CatalogID
	}
	if publishAssetsOptions.AllowDuplicates != nil {
		body["allow_duplicates"] = publishAssetsOptions.AllowDuplicates
	}
	if publishAssetsOptions.Assets != nil {
		body["assets"] = publishAssetsOptions.Assets
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
	if rawResponse != nil {
		err = core.UnmarshalModel(rawResponse, "", &result, UnmarshalCatalogPublishResponse)
		if err != nil {
			return
		}
		response.Result = result
	}

	return
}

// AddDatasourceConnectionOptions : The AddDatasourceConnection options.
type AddDatasourceConnectionOptions struct {
	// The type of data source that you want to add.
	DatasourceType *string `validate:"required"`

	// The name of data source.
	Name *string `validate:"required"`

	// The location of data source that you want to add.
	OriginCountry *string `validate:"required"`

	Properties *PostDatasourceConnectionParametersProperties `validate:"required"`

	AssetCategory *string

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
func (_options *AddDatasourceConnectionOptions) SetDatasourceType(datasourceType string) *AddDatasourceConnectionOptions {
	_options.DatasourceType = core.StringPtr(datasourceType)
	return _options
}

// SetName : Allow user to set Name
func (_options *AddDatasourceConnectionOptions) SetName(name string) *AddDatasourceConnectionOptions {
	_options.Name = core.StringPtr(name)
	return _options
}

// SetOriginCountry : Allow user to set OriginCountry
func (_options *AddDatasourceConnectionOptions) SetOriginCountry(originCountry string) *AddDatasourceConnectionOptions {
	_options.OriginCountry = core.StringPtr(originCountry)
	return _options
}

// SetProperties : Allow user to set Properties
func (_options *AddDatasourceConnectionOptions) SetProperties(properties *PostDatasourceConnectionParametersProperties) *AddDatasourceConnectionOptions {
	_options.Properties = properties
	return _options
}

// SetAssetCategory : Allow user to set AssetCategory
func (_options *AddDatasourceConnectionOptions) SetAssetCategory(assetCategory string) *AddDatasourceConnectionOptions {
	_options.AssetCategory = core.StringPtr(assetCategory)
	return _options
}

// SetHeaders : Allow user to set Headers
func (options *AddDatasourceConnectionOptions) SetHeaders(param map[string]string) *AddDatasourceConnectionOptions {
	options.Headers = param
	return options
}

// CatalogPublishResponseDuplicateAssetsItem : CatalogPublishResponseDuplicateAssetsItem struct
type CatalogPublishResponseDuplicateAssetsItem struct {
	SchemaName *string `json:"schema_name,omitempty"`

	TableName *string `json:"table_name,omitempty"`
}

// UnmarshalCatalogPublishResponseDuplicateAssetsItem unmarshals an instance of CatalogPublishResponseDuplicateAssetsItem from the specified map of raw messages.
func UnmarshalCatalogPublishResponseDuplicateAssetsItem(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(CatalogPublishResponseDuplicateAssetsItem)
	err = core.UnmarshalPrimitive(m, "schema_name", &obj.SchemaName)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "table_name", &obj.TableName)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// CatalogPublishResponseFailedAssetsItem : CatalogPublishResponseFailedAssetsItem struct
type CatalogPublishResponseFailedAssetsItem struct {
	ErrorMsg *string `json:"error_msg,omitempty"`

	SchemaName *string `json:"schema_name,omitempty"`

	TableName *string `json:"table_name,omitempty"`
}

// UnmarshalCatalogPublishResponseFailedAssetsItem unmarshals an instance of CatalogPublishResponseFailedAssetsItem from the specified map of raw messages.
func UnmarshalCatalogPublishResponseFailedAssetsItem(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(CatalogPublishResponseFailedAssetsItem)
	err = core.UnmarshalPrimitive(m, "error_msg", &obj.ErrorMsg)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "schema_name", &obj.SchemaName)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "table_name", &obj.TableName)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// CatalogPublishResponsePublishedAssetsItem : CatalogPublishResponsePublishedAssetsItem struct
type CatalogPublishResponsePublishedAssetsItem struct {
	SchemaName *string `json:"schema_name,omitempty"`

	TableName *string `json:"table_name,omitempty"`

	WkcAssetID *string `json:"wkc_asset_id,omitempty"`
}

// UnmarshalCatalogPublishResponsePublishedAssetsItem unmarshals an instance of CatalogPublishResponsePublishedAssetsItem from the specified map of raw messages.
func UnmarshalCatalogPublishResponsePublishedAssetsItem(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(CatalogPublishResponsePublishedAssetsItem)
	err = core.UnmarshalPrimitive(m, "schema_name", &obj.SchemaName)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "table_name", &obj.TableName)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "wkc_asset_id", &obj.WkcAssetID)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// CheckPolicyStatusV2Options : The CheckPolicyStatusV2 options.
type CheckPolicyStatusV2Options struct {

	// Allows users to set headers on API requests
	Headers map[string]string
}

// NewCheckPolicyStatusV2Options : Instantiate CheckPolicyStatusV2Options
func (*DataVirtualizationV1) NewCheckPolicyStatusV2Options() *CheckPolicyStatusV2Options {
	return &CheckPolicyStatusV2Options{}
}

// SetHeaders : Allow user to set Headers
func (options *CheckPolicyStatusV2Options) SetHeaders(param map[string]string) *CheckPolicyStatusV2Options {
	options.Headers = param
	return options
}

// CheckPolicyStatusV2Response : CheckPolicyStatusV2Response struct
type CheckPolicyStatusV2Response struct {
	Status *string `json:"status" validate:"required"`
}

// UnmarshalCheckPolicyStatusV2Response unmarshals an instance of CheckPolicyStatusV2Response from the specified map of raw messages.
func UnmarshalCheckPolicyStatusV2Response(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(CheckPolicyStatusV2Response)
	err = core.UnmarshalPrimitive(m, "status", &obj.Status)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// DatasourceConnectionsList : DatasourceConnectionsList struct
type DatasourceConnectionsList struct {
	DatasourceConnections []DatasourceConnectionsListDatasourceConnectionsItem `json:"datasource_connections,omitempty"`
}

// UnmarshalDatasourceConnectionsList unmarshals an instance of DatasourceConnectionsList from the specified map of raw messages.
func UnmarshalDatasourceConnectionsList(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(DatasourceConnectionsList)
	err = core.UnmarshalModel(m, "datasource_connections", &obj.DatasourceConnections, UnmarshalDatasourceConnectionsListDatasourceConnectionsItem)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// DatasourceConnectionsListDatasourceConnectionsItem : DatasourceConnectionsListDatasourceConnectionsItem struct
type DatasourceConnectionsListDatasourceConnectionsItem struct {
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

	DataSources []DatasourceConnectionsListDatasourceConnectionsItemDataSourcesItem `json:"data_sources,omitempty"`
}

// UnmarshalDatasourceConnectionsListDatasourceConnectionsItem unmarshals an instance of DatasourceConnectionsListDatasourceConnectionsItem from the specified map of raw messages.
func UnmarshalDatasourceConnectionsListDatasourceConnectionsItem(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(DatasourceConnectionsListDatasourceConnectionsItem)
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
	err = core.UnmarshalModel(m, "data_sources", &obj.DataSources, UnmarshalDatasourceConnectionsListDatasourceConnectionsItemDataSourcesItem)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// DatasourceConnectionsListDatasourceConnectionsItemDataSourcesItem : DatasourceConnectionsListDatasourceConnectionsItemDataSourcesItem struct
type DatasourceConnectionsListDatasourceConnectionsItemDataSourcesItem struct {
	// The identifier of the connection for the Data Virtualization.
	Cid *string `json:"cid,omitempty"`

	// The name of the database.
	Dbname *string `json:"dbname,omitempty"`

	// The connection identifier for the platform.
	ConnectionID *string `json:"connection_id,omitempty"`

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

// UnmarshalDatasourceConnectionsListDatasourceConnectionsItemDataSourcesItem unmarshals an instance of DatasourceConnectionsListDatasourceConnectionsItemDataSourcesItem from the specified map of raw messages.
func UnmarshalDatasourceConnectionsListDatasourceConnectionsItemDataSourcesItem(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(DatasourceConnectionsListDatasourceConnectionsItemDataSourcesItem)
	err = core.UnmarshalPrimitive(m, "cid", &obj.Cid)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "dbname", &obj.Dbname)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "connection_id", &obj.ConnectionID)
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

// DeleteDatasourceConnectionOptions : The DeleteDatasourceConnection options.
type DeleteDatasourceConnectionOptions struct {
	// The connection identifier for the platform..
	ConnectionID *string `validate:"required,ne="`

	// The identifier of the connection for the Data Virtualization..
	Cid *string

	// Allows users to set headers on API requests
	Headers map[string]string
}

// NewDeleteDatasourceConnectionOptions : Instantiate DeleteDatasourceConnectionOptions
func (*DataVirtualizationV1) NewDeleteDatasourceConnectionOptions(connectionID string) *DeleteDatasourceConnectionOptions {
	return &DeleteDatasourceConnectionOptions{
		ConnectionID: core.StringPtr(connectionID),
	}
}

// SetConnectionID : Allow user to set ConnectionID
func (_options *DeleteDatasourceConnectionOptions) SetConnectionID(connectionID string) *DeleteDatasourceConnectionOptions {
	_options.ConnectionID = core.StringPtr(connectionID)
	return _options
}

// SetCid : Allow user to set Cid
func (_options *DeleteDatasourceConnectionOptions) SetCid(cid string) *DeleteDatasourceConnectionOptions {
	_options.Cid = core.StringPtr(cid)
	return _options
}

// SetHeaders : Allow user to set Headers
func (options *DeleteDatasourceConnectionOptions) SetHeaders(param map[string]string) *DeleteDatasourceConnectionOptions {
	options.Headers = param
	return options
}

// DeletePrimaryCatalogOptions : The DeletePrimaryCatalog options.
type DeletePrimaryCatalogOptions struct {
	// The Data Virtualization user name, if the value is PUBLIC, it means revoke access privilege from all Data
	// Virtualization users.
	GUID *string `validate:"required"`

	// Allows users to set headers on API requests
	Headers map[string]string
}

// NewDeletePrimaryCatalogOptions : Instantiate DeletePrimaryCatalogOptions
func (*DataVirtualizationV1) NewDeletePrimaryCatalogOptions(guid string) *DeletePrimaryCatalogOptions {
	return &DeletePrimaryCatalogOptions{
		GUID: core.StringPtr(guid),
	}
}

// SetGUID : Allow user to set GUID
func (_options *DeletePrimaryCatalogOptions) SetGUID(guid string) *DeletePrimaryCatalogOptions {
	_options.GUID = core.StringPtr(guid)
	return _options
}

// SetHeaders : Allow user to set Headers
func (options *DeletePrimaryCatalogOptions) SetHeaders(param map[string]string) *DeletePrimaryCatalogOptions {
	options.Headers = param
	return options
}

// DeleteTableOptions : The DeleteTable options.
type DeleteTableOptions struct {
	// The schema of virtualized table to be deleted.
	VirtualSchema *string `validate:"required"`

	// The name of virtualized table to be deleted.
	VirtualName *string `validate:"required,ne="`

	// Allows users to set headers on API requests
	Headers map[string]string
}

// NewDeleteTableOptions : Instantiate DeleteTableOptions
func (*DataVirtualizationV1) NewDeleteTableOptions(virtualSchema string, virtualName string) *DeleteTableOptions {
	return &DeleteTableOptions{
		VirtualSchema: core.StringPtr(virtualSchema),
		VirtualName: core.StringPtr(virtualName),
	}
}

// SetVirtualSchema : Allow user to set VirtualSchema
func (_options *DeleteTableOptions) SetVirtualSchema(virtualSchema string) *DeleteTableOptions {
	_options.VirtualSchema = core.StringPtr(virtualSchema)
	return _options
}

// SetVirtualName : Allow user to set VirtualName
func (_options *DeleteTableOptions) SetVirtualName(virtualName string) *DeleteTableOptions {
	_options.VirtualName = core.StringPtr(virtualName)
	return _options
}

// SetHeaders : Allow user to set Headers
func (options *DeleteTableOptions) SetHeaders(param map[string]string) *DeleteTableOptions {
	options.Headers = param
	return options
}

// DvaasRevokeRoleFromTableOptions : The DvaasRevokeRoleFromTable options.
type DvaasRevokeRoleFromTableOptions struct {
	// The Data Virtualization role type. Values can be DV_ADMIN, DV_ENGINEER, DV_STEWARD, or DV_WORKER, which correspond
	// to MANAGER, ENGINEER, STEWARD, and USER roles in the user interface.
	RoleName *string `validate:"required,ne="`

	// The virtualized table's name.
	TableName *string `validate:"required"`

	// The virtualized table's schema name.
	TableSchema *string `validate:"required"`

	// Allows users to set headers on API requests
	Headers map[string]string
}

// NewDvaasRevokeRoleFromTableOptions : Instantiate DvaasRevokeRoleFromTableOptions
func (*DataVirtualizationV1) NewDvaasRevokeRoleFromTableOptions(roleName string, tableName string, tableSchema string) *DvaasRevokeRoleFromTableOptions {
	return &DvaasRevokeRoleFromTableOptions{
		RoleName: core.StringPtr(roleName),
		TableName: core.StringPtr(tableName),
		TableSchema: core.StringPtr(tableSchema),
	}
}

// SetRoleName : Allow user to set RoleName
func (_options *DvaasRevokeRoleFromTableOptions) SetRoleName(roleName string) *DvaasRevokeRoleFromTableOptions {
	_options.RoleName = core.StringPtr(roleName)
	return _options
}

// SetTableName : Allow user to set TableName
func (_options *DvaasRevokeRoleFromTableOptions) SetTableName(tableName string) *DvaasRevokeRoleFromTableOptions {
	_options.TableName = core.StringPtr(tableName)
	return _options
}

// SetTableSchema : Allow user to set TableSchema
func (_options *DvaasRevokeRoleFromTableOptions) SetTableSchema(tableSchema string) *DvaasRevokeRoleFromTableOptions {
	_options.TableSchema = core.StringPtr(tableSchema)
	return _options
}

// SetHeaders : Allow user to set Headers
func (options *DvaasRevokeRoleFromTableOptions) SetHeaders(param map[string]string) *DvaasRevokeRoleFromTableOptions {
	options.Headers = param
	return options
}

// DvaasVirtualizeTableOptions : The DvaasVirtualizeTable options.
type DvaasVirtualizeTableOptions struct {
	// The name of the source table.
	SourceName *string `validate:"required"`

	SourceTableDef []VirtualizeTableParameterSourceTableDefItem `validate:"required"`

	Sources []string `validate:"required"`

	// The name of the table that will be virtualized.
	VirtualName *string `validate:"required"`

	// The schema of the table that will be virtualized.
	VirtualSchema *string `validate:"required"`

	VirtualTableDef []VirtualizeTableParameterVirtualTableDefItem `validate:"required"`

	// The columns that are included in the source table.
	IsIncludedColumns *string

	// Determines whether to replace columns in the virtualized table.
	Replace *bool

	// Allows users to set headers on API requests
	Headers map[string]string
}

// NewDvaasVirtualizeTableOptions : Instantiate DvaasVirtualizeTableOptions
func (*DataVirtualizationV1) NewDvaasVirtualizeTableOptions(sourceName string, sourceTableDef []VirtualizeTableParameterSourceTableDefItem, sources []string, virtualName string, virtualSchema string, virtualTableDef []VirtualizeTableParameterVirtualTableDefItem) *DvaasVirtualizeTableOptions {
	return &DvaasVirtualizeTableOptions{
		SourceName: core.StringPtr(sourceName),
		SourceTableDef: sourceTableDef,
		Sources: sources,
		VirtualName: core.StringPtr(virtualName),
		VirtualSchema: core.StringPtr(virtualSchema),
		VirtualTableDef: virtualTableDef,
	}
}

// SetSourceName : Allow user to set SourceName
func (_options *DvaasVirtualizeTableOptions) SetSourceName(sourceName string) *DvaasVirtualizeTableOptions {
	_options.SourceName = core.StringPtr(sourceName)
	return _options
}

// SetSourceTableDef : Allow user to set SourceTableDef
func (_options *DvaasVirtualizeTableOptions) SetSourceTableDef(sourceTableDef []VirtualizeTableParameterSourceTableDefItem) *DvaasVirtualizeTableOptions {
	_options.SourceTableDef = sourceTableDef
	return _options
}

// SetSources : Allow user to set Sources
func (_options *DvaasVirtualizeTableOptions) SetSources(sources []string) *DvaasVirtualizeTableOptions {
	_options.Sources = sources
	return _options
}

// SetVirtualName : Allow user to set VirtualName
func (_options *DvaasVirtualizeTableOptions) SetVirtualName(virtualName string) *DvaasVirtualizeTableOptions {
	_options.VirtualName = core.StringPtr(virtualName)
	return _options
}

// SetVirtualSchema : Allow user to set VirtualSchema
func (_options *DvaasVirtualizeTableOptions) SetVirtualSchema(virtualSchema string) *DvaasVirtualizeTableOptions {
	_options.VirtualSchema = core.StringPtr(virtualSchema)
	return _options
}

// SetVirtualTableDef : Allow user to set VirtualTableDef
func (_options *DvaasVirtualizeTableOptions) SetVirtualTableDef(virtualTableDef []VirtualizeTableParameterVirtualTableDefItem) *DvaasVirtualizeTableOptions {
	_options.VirtualTableDef = virtualTableDef
	return _options
}

// SetIsIncludedColumns : Allow user to set IsIncludedColumns
func (_options *DvaasVirtualizeTableOptions) SetIsIncludedColumns(isIncludedColumns string) *DvaasVirtualizeTableOptions {
	_options.IsIncludedColumns = core.StringPtr(isIncludedColumns)
	return _options
}

// SetReplace : Allow user to set Replace
func (_options *DvaasVirtualizeTableOptions) SetReplace(replace bool) *DvaasVirtualizeTableOptions {
	_options.Replace = core.BoolPtr(replace)
	return _options
}

// SetHeaders : Allow user to set Headers
func (options *DvaasVirtualizeTableOptions) SetHeaders(param map[string]string) *DvaasVirtualizeTableOptions {
	options.Headers = param
	return options
}

// GetPrimaryCatalogOptions : The GetPrimaryCatalog options.
type GetPrimaryCatalogOptions struct {

	// Allows users to set headers on API requests
	Headers map[string]string
}

// NewGetPrimaryCatalogOptions : Instantiate GetPrimaryCatalogOptions
func (*DataVirtualizationV1) NewGetPrimaryCatalogOptions() *GetPrimaryCatalogOptions {
	return &GetPrimaryCatalogOptions{}
}

// SetHeaders : Allow user to set Headers
func (options *GetPrimaryCatalogOptions) SetHeaders(param map[string]string) *GetPrimaryCatalogOptions {
	options.Headers = param
	return options
}

// GrantRolesToVirtualizedTableOptions : The GrantRolesToVirtualizedTable options.
type GrantRolesToVirtualizedTableOptions struct {
	// The name of the virtualized table.
	TableName *string `validate:"required"`

	// The schema of the virtualized table.
	TableSchema *string `validate:"required"`

	// The identifier of the authorization, if grant access to all users, the value is PUBLIC, othervise the value is the
	// data virtualization username.
	RoleName *string

	// Allows users to set headers on API requests
	Headers map[string]string
}

// NewGrantRolesToVirtualizedTableOptions : Instantiate GrantRolesToVirtualizedTableOptions
func (*DataVirtualizationV1) NewGrantRolesToVirtualizedTableOptions(tableName string, tableSchema string) *GrantRolesToVirtualizedTableOptions {
	return &GrantRolesToVirtualizedTableOptions{
		TableName: core.StringPtr(tableName),
		TableSchema: core.StringPtr(tableSchema),
	}
}

// SetTableName : Allow user to set TableName
func (_options *GrantRolesToVirtualizedTableOptions) SetTableName(tableName string) *GrantRolesToVirtualizedTableOptions {
	_options.TableName = core.StringPtr(tableName)
	return _options
}

// SetTableSchema : Allow user to set TableSchema
func (_options *GrantRolesToVirtualizedTableOptions) SetTableSchema(tableSchema string) *GrantRolesToVirtualizedTableOptions {
	_options.TableSchema = core.StringPtr(tableSchema)
	return _options
}

// SetRoleName : Allow user to set RoleName
func (_options *GrantRolesToVirtualizedTableOptions) SetRoleName(roleName string) *GrantRolesToVirtualizedTableOptions {
	_options.RoleName = core.StringPtr(roleName)
	return _options
}

// SetHeaders : Allow user to set Headers
func (options *GrantRolesToVirtualizedTableOptions) SetHeaders(param map[string]string) *GrantRolesToVirtualizedTableOptions {
	options.Headers = param
	return options
}

// GrantUserToVirtualTableOptions : The GrantUserToVirtualTable options.
type GrantUserToVirtualTableOptions struct {
	// The name of the virtualized table.
	TableName *string `validate:"required"`

	// The schema of the virtualized table.
	TableSchema *string `validate:"required"`

	// The identifier of the authorization, if grant access to all users, the value is PUBLIC, othervise the value is the
	// data virtualization username.
	Authid *string `validate:"required"`

	// Allows users to set headers on API requests
	Headers map[string]string
}

// NewGrantUserToVirtualTableOptions : Instantiate GrantUserToVirtualTableOptions
func (*DataVirtualizationV1) NewGrantUserToVirtualTableOptions(tableName string, tableSchema string, authid string) *GrantUserToVirtualTableOptions {
	return &GrantUserToVirtualTableOptions{
		TableName: core.StringPtr(tableName),
		TableSchema: core.StringPtr(tableSchema),
		Authid: core.StringPtr(authid),
	}
}

// SetTableName : Allow user to set TableName
func (_options *GrantUserToVirtualTableOptions) SetTableName(tableName string) *GrantUserToVirtualTableOptions {
	_options.TableName = core.StringPtr(tableName)
	return _options
}

// SetTableSchema : Allow user to set TableSchema
func (_options *GrantUserToVirtualTableOptions) SetTableSchema(tableSchema string) *GrantUserToVirtualTableOptions {
	_options.TableSchema = core.StringPtr(tableSchema)
	return _options
}

// SetAuthid : Allow user to set Authid
func (_options *GrantUserToVirtualTableOptions) SetAuthid(authid string) *GrantUserToVirtualTableOptions {
	_options.Authid = core.StringPtr(authid)
	return _options
}

// SetHeaders : Allow user to set Headers
func (options *GrantUserToVirtualTableOptions) SetHeaders(param map[string]string) *GrantUserToVirtualTableOptions {
	options.Headers = param
	return options
}

// ListDatasourceConnectionsOptions : The ListDatasourceConnections options.
type ListDatasourceConnectionsOptions struct {

	// Allows users to set headers on API requests
	Headers map[string]string
}

// NewListDatasourceConnectionsOptions : Instantiate ListDatasourceConnectionsOptions
func (*DataVirtualizationV1) NewListDatasourceConnectionsOptions() *ListDatasourceConnectionsOptions {
	return &ListDatasourceConnectionsOptions{}
}

// SetHeaders : Allow user to set Headers
func (options *ListDatasourceConnectionsOptions) SetHeaders(param map[string]string) *ListDatasourceConnectionsOptions {
	options.Headers = param
	return options
}

// ListTablesForRoleOptions : The ListTablesForRole options.
type ListTablesForRoleOptions struct {
	// Data Virtualization has four roles: MANAGER, STEWARD, ENGINEER and USER The value of rolename should be one of them.
	Rolename *string `validate:"required"`

	// Allows users to set headers on API requests
	Headers map[string]string
}

// NewListTablesForRoleOptions : Instantiate ListTablesForRoleOptions
func (*DataVirtualizationV1) NewListTablesForRoleOptions(rolename string) *ListTablesForRoleOptions {
	return &ListTablesForRoleOptions{
		Rolename: core.StringPtr(rolename),
	}
}

// SetRolename : Allow user to set Rolename
func (_options *ListTablesForRoleOptions) SetRolename(rolename string) *ListTablesForRoleOptions {
	_options.Rolename = core.StringPtr(rolename)
	return _options
}

// SetHeaders : Allow user to set Headers
func (options *ListTablesForRoleOptions) SetHeaders(param map[string]string) *ListTablesForRoleOptions {
	options.Headers = param
	return options
}

// PostDatasourceConnection : PostDatasourceConnection struct
type PostDatasourceConnection struct {
	// The identifier of data source connection.
	ConnectionID *string `json:"connection_id" validate:"required"`

	// The type of data source that you want to add.
	DatasourceType *string `json:"datasource_type" validate:"required"`

	// The name of data source.
	Name *string `json:"name" validate:"required"`
}

// UnmarshalPostDatasourceConnection unmarshals an instance of PostDatasourceConnection from the specified map of raw messages.
func UnmarshalPostDatasourceConnection(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(PostDatasourceConnection)
	err = core.UnmarshalPrimitive(m, "connection_id", &obj.ConnectionID)
	if err != nil {
		return
	}
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

// PostDatasourceConnectionParametersProperties : PostDatasourceConnectionParametersProperties struct
type PostDatasourceConnectionParametersProperties struct {
	AccessToken *string `json:"access_token,omitempty"`

	AccountName *string `json:"account_name,omitempty"`

	APIKey *string `json:"api_key,omitempty"`

	AuthType *string `json:"auth_type,omitempty"`

	ClientID *string `json:"client_id,omitempty"`

	ClientSecret *string `json:"client_secret,omitempty"`

	Collection *string `json:"collection,omitempty"`

	Credentials *string `json:"credentials,omitempty"`

	Database *string `json:"database,omitempty"`

	Host *string `json:"host,omitempty"`

	HTTPPath *string `json:"http_path,omitempty"`

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
	err = core.UnmarshalPrimitive(m, "api_key", &obj.APIKey)
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
	err = core.UnmarshalPrimitive(m, "http_path", &obj.HTTPPath)
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

// PostPrimaryCatalogOptions : The PostPrimaryCatalog options.
type PostPrimaryCatalogOptions struct {
	GUID *string `validate:"required"`

	// Allows users to set headers on API requests
	Headers map[string]string
}

// NewPostPrimaryCatalogOptions : Instantiate PostPrimaryCatalogOptions
func (*DataVirtualizationV1) NewPostPrimaryCatalogOptions(guid string) *PostPrimaryCatalogOptions {
	return &PostPrimaryCatalogOptions{
		GUID: core.StringPtr(guid),
	}
}

// SetGUID : Allow user to set GUID
func (_options *PostPrimaryCatalogOptions) SetGUID(guid string) *PostPrimaryCatalogOptions {
	_options.GUID = core.StringPtr(guid)
	return _options
}

// SetHeaders : Allow user to set Headers
func (options *PostPrimaryCatalogOptions) SetHeaders(param map[string]string) *PostPrimaryCatalogOptions {
	options.Headers = param
	return options
}

// PostPrimaryCatalogParametersAssetsItem : PostPrimaryCatalogParametersAssetsItem struct
type PostPrimaryCatalogParametersAssetsItem struct {
	Schema *string `json:"schema" validate:"required"`

	Table *string `json:"table" validate:"required"`
}

// NewPostPrimaryCatalogParametersAssetsItem : Instantiate PostPrimaryCatalogParametersAssetsItem (Generic Model Constructor)
func (*DataVirtualizationV1) NewPostPrimaryCatalogParametersAssetsItem(schema string, table string) (_model *PostPrimaryCatalogParametersAssetsItem, err error) {
	_model = &PostPrimaryCatalogParametersAssetsItem{
		Schema: core.StringPtr(schema),
		Table: core.StringPtr(table),
	}
	err = core.ValidateStruct(_model, "required parameters")
	return
}

// UnmarshalPostPrimaryCatalogParametersAssetsItem unmarshals an instance of PostPrimaryCatalogParametersAssetsItem from the specified map of raw messages.
func UnmarshalPostPrimaryCatalogParametersAssetsItem(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(PostPrimaryCatalogParametersAssetsItem)
	err = core.UnmarshalPrimitive(m, "schema", &obj.Schema)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "table", &obj.Table)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// PrimaryCatalogInfoEntity : PrimaryCatalogInfoEntity struct
type PrimaryCatalogInfoEntity struct {
	AutoProfiling *bool `json:"auto_profiling,omitempty"`

	BssAccountID *string `json:"bss_account_id,omitempty"`

	CapacityLimit *int64 `json:"capacity_limit,omitempty"`

	Description *string `json:"description,omitempty"`

	Generator *string `json:"generator,omitempty"`

	IsGoverned *bool `json:"is_governed,omitempty"`

	Name *string `json:"name,omitempty"`
}

// UnmarshalPrimaryCatalogInfoEntity unmarshals an instance of PrimaryCatalogInfoEntity from the specified map of raw messages.
func UnmarshalPrimaryCatalogInfoEntity(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(PrimaryCatalogInfoEntity)
	err = core.UnmarshalPrimitive(m, "auto_profiling", &obj.AutoProfiling)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "bss_account_id", &obj.BssAccountID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "capacity_limit", &obj.CapacityLimit)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "description", &obj.Description)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "generator", &obj.Generator)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "is_governed", &obj.IsGoverned)
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

// PrimaryCatalogInfoMetadata : PrimaryCatalogInfoMetadata struct
type PrimaryCatalogInfoMetadata struct {
	CreateTime *string `json:"create_time,omitempty"`

	CreatorID *string `json:"creator_id,omitempty"`

	GUID *string `json:"guid,omitempty"`

	URL *string `json:"url,omitempty"`
}

// UnmarshalPrimaryCatalogInfoMetadata unmarshals an instance of PrimaryCatalogInfoMetadata from the specified map of raw messages.
func UnmarshalPrimaryCatalogInfoMetadata(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(PrimaryCatalogInfoMetadata)
	err = core.UnmarshalPrimitive(m, "create_time", &obj.CreateTime)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "creator_id", &obj.CreatorID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "guid", &obj.GUID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "url", &obj.URL)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// PublishAssetsOptions : The PublishAssets options.
type PublishAssetsOptions struct {
	CatalogID *string `validate:"required"`

	// The type of data source that you want to add.
	AllowDuplicates *bool `validate:"required"`

	Assets []PostPrimaryCatalogParametersAssetsItem `validate:"required"`

	// Allows users to set headers on API requests
	Headers map[string]string
}

// NewPublishAssetsOptions : Instantiate PublishAssetsOptions
func (*DataVirtualizationV1) NewPublishAssetsOptions(catalogID string, allowDuplicates bool, assets []PostPrimaryCatalogParametersAssetsItem) *PublishAssetsOptions {
	return &PublishAssetsOptions{
		CatalogID: core.StringPtr(catalogID),
		AllowDuplicates: core.BoolPtr(allowDuplicates),
		Assets: assets,
	}
}

// SetCatalogID : Allow user to set CatalogID
func (_options *PublishAssetsOptions) SetCatalogID(catalogID string) *PublishAssetsOptions {
	_options.CatalogID = core.StringPtr(catalogID)
	return _options
}

// SetAllowDuplicates : Allow user to set AllowDuplicates
func (_options *PublishAssetsOptions) SetAllowDuplicates(allowDuplicates bool) *PublishAssetsOptions {
	_options.AllowDuplicates = core.BoolPtr(allowDuplicates)
	return _options
}

// SetAssets : Allow user to set Assets
func (_options *PublishAssetsOptions) SetAssets(assets []PostPrimaryCatalogParametersAssetsItem) *PublishAssetsOptions {
	_options.Assets = assets
	return _options
}

// SetHeaders : Allow user to set Headers
func (options *PublishAssetsOptions) SetHeaders(param map[string]string) *PublishAssetsOptions {
	options.Headers = param
	return options
}

// RevokeUserFromObjectOptions : The RevokeUserFromObject options.
type RevokeUserFromObjectOptions struct {
	// The Data Virtualization user name, if the value is PUBLIC, it means revoke access privilege from all Data
	// Virtualization users.
	Authid *string `validate:"required,ne="`

	// The virtualized table's name.
	TableName *string `validate:"required"`

	// The virtualized table's schema name.
	TableSchema *string `validate:"required"`

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
func (_options *RevokeUserFromObjectOptions) SetAuthid(authid string) *RevokeUserFromObjectOptions {
	_options.Authid = core.StringPtr(authid)
	return _options
}

// SetTableName : Allow user to set TableName
func (_options *RevokeUserFromObjectOptions) SetTableName(tableName string) *RevokeUserFromObjectOptions {
	_options.TableName = core.StringPtr(tableName)
	return _options
}

// SetTableSchema : Allow user to set TableSchema
func (_options *RevokeUserFromObjectOptions) SetTableSchema(tableSchema string) *RevokeUserFromObjectOptions {
	_options.TableSchema = core.StringPtr(tableSchema)
	return _options
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

// TurnOnPolicyV2Options : The TurnOnPolicyV2 options.
type TurnOnPolicyV2Options struct {
	// Set the status of WKC policy.
	Status *string `validate:"required"`

	// Allows users to set headers on API requests
	Headers map[string]string
}

// NewTurnOnPolicyV2Options : Instantiate TurnOnPolicyV2Options
func (*DataVirtualizationV1) NewTurnOnPolicyV2Options(status string) *TurnOnPolicyV2Options {
	return &TurnOnPolicyV2Options{
		Status: core.StringPtr(status),
	}
}

// SetStatus : Allow user to set Status
func (_options *TurnOnPolicyV2Options) SetStatus(status string) *TurnOnPolicyV2Options {
	_options.Status = core.StringPtr(status)
	return _options
}

// SetHeaders : Allow user to set Headers
func (options *TurnOnPolicyV2Options) SetHeaders(param map[string]string) *TurnOnPolicyV2Options {
	options.Headers = param
	return options
}

// TurnOnPolicyV2Response : TurnOnPolicyV2Response struct
type TurnOnPolicyV2Response struct {
	Status *string `json:"status" validate:"required"`
}

// UnmarshalTurnOnPolicyV2Response unmarshals an instance of TurnOnPolicyV2Response from the specified map of raw messages.
func UnmarshalTurnOnPolicyV2Response(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(TurnOnPolicyV2Response)
	err = core.UnmarshalPrimitive(m, "status", &obj.Status)
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
func (*DataVirtualizationV1) NewVirtualizeTableParameterSourceTableDefItem(columnName string, columnType string) (_model *VirtualizeTableParameterSourceTableDefItem, err error) {
	_model = &VirtualizeTableParameterSourceTableDefItem{
		ColumnName: core.StringPtr(columnName),
		ColumnType: core.StringPtr(columnType),
	}
	err = core.ValidateStruct(_model, "required parameters")
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
func (*DataVirtualizationV1) NewVirtualizeTableParameterVirtualTableDefItem(columnName string, columnType string) (_model *VirtualizeTableParameterVirtualTableDefItem, err error) {
	_model = &VirtualizeTableParameterVirtualTableDefItem{
		ColumnName: core.StringPtr(columnName),
		ColumnType: core.StringPtr(columnType),
	}
	err = core.ValidateStruct(_model, "required parameters")
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
	// The name of the table that is virtualized.
	TableName *string `json:"table_name" validate:"required"`

	// The schema of the table that is virtualized.
	SchemaName *string `json:"schema_name" validate:"required"`
}

// UnmarshalVirtualizeTableResponse unmarshals an instance of VirtualizeTableResponse from the specified map of raw messages.
func UnmarshalVirtualizeTableResponse(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(VirtualizeTableResponse)
	err = core.UnmarshalPrimitive(m, "table_name", &obj.TableName)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "schema_name", &obj.SchemaName)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// CatalogPublishResponse : CatalogPublishResponse struct
type CatalogPublishResponse struct {
	DuplicateAssets []CatalogPublishResponseDuplicateAssetsItem `json:"duplicate_assets,omitempty"`

	FailedAssets []CatalogPublishResponseFailedAssetsItem `json:"failed_assets,omitempty"`

	PublishedAssets []CatalogPublishResponsePublishedAssetsItem `json:"published_assets,omitempty"`
}

// UnmarshalCatalogPublishResponse unmarshals an instance of CatalogPublishResponse from the specified map of raw messages.
func UnmarshalCatalogPublishResponse(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(CatalogPublishResponse)
	err = core.UnmarshalModel(m, "duplicate_assets", &obj.DuplicateAssets, UnmarshalCatalogPublishResponseDuplicateAssetsItem)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "failed_assets", &obj.FailedAssets, UnmarshalCatalogPublishResponseFailedAssetsItem)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "published_assets", &obj.PublishedAssets, UnmarshalCatalogPublishResponsePublishedAssetsItem)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// PostPrimaryCatalog : PostPrimaryCatalog struct
type PostPrimaryCatalog struct {
	GUID *string `json:"guid" validate:"required"`

	Name *string `json:"name" validate:"required"`

	Description *string `json:"description" validate:"required"`
}

// UnmarshalPostPrimaryCatalog unmarshals an instance of PostPrimaryCatalog from the specified map of raw messages.
func UnmarshalPostPrimaryCatalog(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(PostPrimaryCatalog)
	err = core.UnmarshalPrimitive(m, "guid", &obj.GUID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "name", &obj.Name)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "description", &obj.Description)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// PrimaryCatalogInfo : PrimaryCatalogInfo struct
type PrimaryCatalogInfo struct {
	Entity *PrimaryCatalogInfoEntity `json:"entity,omitempty"`

	Href *string `json:"href,omitempty"`

	Metadata *PrimaryCatalogInfoMetadata `json:"metadata,omitempty"`
}

// UnmarshalPrimaryCatalogInfo unmarshals an instance of PrimaryCatalogInfo from the specified map of raw messages.
func UnmarshalPrimaryCatalogInfo(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(PrimaryCatalogInfo)
	err = core.UnmarshalModel(m, "entity", &obj.Entity, UnmarshalPrimaryCatalogInfoEntity)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "href", &obj.Href)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "metadata", &obj.Metadata, UnmarshalPrimaryCatalogInfoMetadata)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}
