package events

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestNewPublisherValidation(t *testing.T) {
	publisher, err := NewPublisher(context.Background(), false, "", "")
	if err != nil {
		t.Fatalf("disabled NewPublisher() error = %v", err)
	}
	if _, ok := publisher.(NoopPublisher); !ok {
		t.Fatalf("disabled publisher type = %T", publisher)
	}
	publisher.Emit(context.Background(), Event{})
	if _, err := NewPublisher(context.Background(), true, "region", ""); err == nil {
		t.Fatal("missing topic ARN accepted")
	}
	if _, err := NewPublisher(context.Background(), true, "", "topic"); err == nil {
		t.Fatal("missing region accepted")
	}
}

func TestSNSPublishSignsAndHandlesResponses(t *testing.T) {
	var body string
	publisher := &SNSPublisher{
		topicARN: "arn:aws:sns:ap-southeast-1:123:events",
		region:   "ap-southeast-1",
		creds: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "key", SecretAccessKey: "secret", Source: "test"}, nil
		}),
		client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			data, _ := io.ReadAll(req.Body)
			body = string(data)
			if req.Header.Get("Authorization") == "" {
				t.Fatal("request was not signed")
			}
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("ok")), Header: make(http.Header)}, nil
		})},
	}
	if err := publisher.publish(context.Background(), `{"event":true}`); err != nil {
		t.Fatalf("publish() error = %v", err)
	}
	if !strings.Contains(body, "Action=Publish") || !strings.Contains(body, "TopicArn=") || !strings.Contains(body, "Message=") {
		t.Fatalf("form body = %q", body)
	}

	publisher.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusInternalServerError, Body: io.NopCloser(strings.NewReader("failed")), Header: make(http.Header)}, nil
	})
	if err := publisher.publish(context.Background(), "message"); err == nil {
		t.Fatal("non-2xx response accepted")
	}
	publisher.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("offline") })
	if err := publisher.publish(context.Background(), "message"); err == nil {
		t.Fatal("transport error accepted")
	}
	publisher.creds = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) { return aws.Credentials{}, errors.New("no credentials") })
	if err := publisher.publish(context.Background(), "message"); err == nil {
		t.Fatal("credential error accepted")
	}
}

func TestSNSPublisherEmitDefaultsAndRejectsInvalidEvents(t *testing.T) {
	received := make(chan string, 1)
	publisher := &SNSPublisher{
		topicARN: "arn:aws:sns:ap-southeast-1:123:events",
		region:   "ap-southeast-1",
		creds: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "key", SecretAccessKey: "secret", Source: "test"}, nil
		}),
		client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			data, _ := io.ReadAll(req.Body)
			received <- string(data)
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("ok")), Header: make(http.Header)}, nil
		})},
	}
	publisher.Emit(context.Background(), Event{EventType: "PlanApproved"})
	select {
	case form := <-received:
		if !strings.Contains(form, "PlanApproved") || !strings.Contains(form, SchemaVersion) || !strings.Contains(form, "agent-controlplane") {
			t.Fatalf("published form = %q", form)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for asynchronous publish")
	}
	publisher.Emit(context.Background(), Event{})
	if got := newID(); len(got) != 32 {
		t.Fatalf("newID() length = %d", len(got))
	}
}
