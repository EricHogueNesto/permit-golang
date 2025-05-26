package enforcement

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/permitio/permit-golang/pkg/errors"
	"go.uber.org/zap"
)

type (
	URL    string
	Method string
	Tenant string
)

type CheckUrlResponse struct {
	Allow  bool                   `json:"allow"`
	Query  map[string]interface{} `json:"query"`
	Debug  map[string]interface{} `json:"debug"`
	Result bool                   `json:"result"`
}

type CheckUrlRequest struct {
	User    User              `json:"user"`
	URL     URL               `json:"url"`
	Method  Method            `json:"http_method"`
	Tenant  Tenant            `json:"tenant"`
	Context map[string]string `json:"context"`
}

func NewCheckUrlRequest(user User, url URL, method Method, tenant Tenant, context map[string]string) *CheckUrlRequest {
	return &CheckUrlRequest{
		User:    user,
		URL:     url,
		Method:  method,
		Tenant:  tenant,
		Context: context,
	}
}

func newJsonCheckUrlRequest(opaUrl string, user User, url URL, method Method, tenant Tenant, context map[string]string) ([]byte, error) {
	allowedUrlReq := NewCheckUrlRequest(user, url, method, tenant, context)
	var genericAllowedUrlReq interface{} = allowedUrlReq
	if opaUrl != "" {
		genericAllowedUrlReq = &struct {
			Input *CheckUrlRequest `json:"input"`
		}{allowedUrlReq}
	}
	jsonAllowedUrlReq, err := json.Marshal(genericAllowedUrlReq)
	if err != nil {
		return nil, err
	}
	return jsonAllowedUrlReq, nil
}

func (e *PermitEnforcer) getAllowedUrlEndpoint() string {
	return e.getEndpointByPolicyPackage(allowedUrlPackage)
}

func (e *PermitEnforcer) parseCheckUrlResponse(res *http.Response) (*CheckUrlResponse, error) {
	var result CheckUrlResponse
	err := errors.HttpErrorHandle(nil, res)
	if err != nil {
		responseBodyZap := zap.String("response_body", "")
		if permitErr, ok := err.(errors.PermitError); ok {
			responseBodyZap = zap.String("response_body", permitErr.ResponseBody)
		}
		e.logger.Error("erroneous http response from PDP for Permit.AllowedUrl()", zap.Error(err), responseBodyZap)
		return nil, err
	}

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		permitError := errors.NewPermitUnexpectedError(err, nil)
		e.logger.Error("error reading Permit.AllowedUrl() response from PDP", zap.Error(permitError))
		return nil, permitError
	}

	if e.config.GetOpaUrl() != "" {
		opaStruct := &struct {
			Result *CheckUrlResponse `json:"result"`
		}{&result}

		if err := json.Unmarshal(bodyBytes, opaStruct); err != nil {
			permitError := errors.NewPermitUnexpectedError(err, nil)
			e.logger.Error("error unmarshalling Permit.AllowedUrl() response from OPA", zap.Error(permitError))
			return nil, err
		}
	} else {
		if err := json.Unmarshal(bodyBytes, &result); err != nil {
			permitError := errors.NewPermitUnexpectedError(err, nil)
			e.logger.Error("error unmarshalling Permit.AllowedUrl() response from PDP", zap.Error(permitError))
			return nil, permitError
		}
	}

	return &result, nil
}

func (e *PermitEnforcer) CheckUrl(user User, url URL, method Method, tenant Tenant, additionalContext ...map[string]string) (bool, error) {
	reqAuthValue := "Bearer " + e.config.GetToken()

	if additionalContext == nil {
		additionalContext = make([]map[string]string, 0)
		additionalContext = append(additionalContext, make(map[string]string))
	}
	jsonAllowedUrlReq, err := newJsonCheckUrlRequest(e.config.GetOpaUrl(), user, url, method, tenant, additionalContext[0])
	if err != nil {
		permitError := errors.NewPermitUnexpectedError(err, nil)
		e.logger.Error("error marshalling Permit.AllowedUrl() request", zap.Error(permitError))
		return false, permitError
	}
	reqBody := bytes.NewBuffer(jsonAllowedUrlReq)
	httpRequest, err := http.NewRequest(reqMethod, e.getAllowedUrlEndpoint(), reqBody)
	if err != nil {
		permitError := errors.NewPermitUnexpectedError(err, nil)
		e.logger.Error("error creating Permit.AllowedUrl() request", zap.Error(permitError))
		return false, permitError
	}
	httpRequest.Header.Set(reqContentTypeKey, reqContentTypeValue)
	httpRequest.Header.Set(reqAuthKey, reqAuthValue)
	res, err := e.client.Do(httpRequest)
	if err != nil {
		permitError := errors.NewPermitUnexpectedError(err, res)
		e.logger.Error("error sending Permit.AllowedUrl() request to PDP", zap.Error(permitError))
		return false, permitError
	}
	result, err := e.parseCheckUrlResponse(res)
	if err != nil {
		return false, err
	}
	return result.Allow, nil
}
