// Package queries contains queries to get all messages from a chat
package queries

import (
	"github.com/skycoin/skywire-utilities/pkg/cipher"
	"github.com/skycoin/skywire/cmd/apps/skychat/internal/domain/chat"
	"github.com/skycoin/skywire/cmd/apps/skychat/internal/domain/message"
)

// GetAllMessagesFromChatRequest Model of the Handler
type GetAllMessagesFromChatRequest struct {
	pk cipher.PubKey
}

// GetAllMessagesFromChatResult is the return model of Chat Query Handlers
type GetAllMessagesFromChatResult struct {
	messages []message.Message
}

// GetAllMessagesFromChatRequestHandler provides an interfaces to handle a GetAllMessagesFromChatRequest and return a *GetAllMessagesFromChatResult
type GetAllMessagesFromChatRequestHandler interface {
	Handle(query GetAllMessagesFromChatRequest) (GetAllMessagesFromChatResult, error)
}

type getAllMessagesFromChatRequestHandler struct {
	repo chat.Repository
}

// NewGetAllMessagesFromChatRequestHandler Handler Constructor
func NewGetAllMessagesFromChatRequestHandler(repo chat.Repository) GetAllMessagesFromChatRequestHandler {
	return getAllMessagesFromChatRequestHandler{repo: repo}
}

// Handle Handlers the GetAllMessagesFromChatRequest query
func (h getAllMessagesFromChatRequestHandler) Handle(query GetAllMessagesFromChatRequest) (GetAllMessagesFromChatResult, error) {
	var result GetAllMessagesFromChatResult

	chat, err := h.repo.GetByPK(query.pk)
	if err != nil {
		return result, err
	}

	msgs := chat.GetMessages()

	if msgs != nil {
		result = GetAllMessagesFromChatResult{messages: msgs}
	}
	return result, err
}
