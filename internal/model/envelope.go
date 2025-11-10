package model

type Envelope struct {
	Ok    bool        `json:"ok"`
	Data  interface{} `json:"data"`
	Error *ErrObj     `json:"error"`
}

type ErrObj struct {
	Code    string      `json:"code"`
	Message string      `json:"message"`
	Details interface{} `json:"details,omitempty"`
}

func OK(data interface{}) Envelope {
	return Envelope{Ok: true, Data: data, Error: nil}
}
func Fail(code, msg string, details interface{}) Envelope {
	return Envelope{Ok: false, Data: nil, Error: &ErrObj{Code: code, Message: msg, Details: details}}
}
