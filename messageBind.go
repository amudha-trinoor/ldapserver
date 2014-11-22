package ldapserver

// a BindRequest struct
type BindRequest struct {
	Version  int
	Login    []byte
	Password []byte
}

func (r *BindRequest) GetLogin() []byte {
	return r.Login
}

func (r *BindRequest) GetPassword() []byte {
	return r.Password
}

// BindResponse consists simply of an indication from the server of the
// status of the client's request for authentication
type BindResponse struct {
	ldapResult
	serverSaslCreds string
}

func NewBindResponse(messageID int, resultCode int) BindResponse {
	r := BindResponse{}
	r.MessageID = messageID
	r.ResultCode = resultCode
	return r
}

func (r *BindResponse) Bytes() []byte {
	return newMessagePacket(r).Bytes()
}