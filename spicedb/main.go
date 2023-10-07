package main

import (
	"context"
	"log"

	pb "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/authzed/authzed-go/v1"
	"github.com/authzed/grpcutil"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const schema = `
definition anonymous {}
definition user {}

definition team {
	relation member: user
}
  
definition post {
	relation reader: user | team#member | anonymous:*
	relation writer: user

	permission read = reader + writer
	permission write = writer
}`

func main() {
	logrus.SetLevel(logrus.DebugLevel)
	helper, err := NewSpiceDBHelper("localhost:50051", "foobar")
	if err != nil {
		log.Fatalf("unable to initialize client: %s", err)
	}

	if err = helper.CreateSchema(); err != nil {
		log.Fatalf("unable to create schema: %s", err)
	}

	logrus.Debug("Add user emilia writer post 1")
	if err := helper.CreateRelation(
		Subject{Type: "user", ID: "emilia"},
		"writer",
		Resource{Type: "post", ID: "1"},
	); err != nil {
		logrus.Fatal(err)
	}

	logrus.Debug("Add user dries member team engineering")
	if err := helper.CreateRelation(
		Subject{Type: "user", ID: "dries"},
		"member",
		Resource{Type: "team", ID: "engineering"},
	); err != nil {
		logrus.Fatal(err)
	}

	logrus.Debug("Add team engineering reader of post 1")
	if err := helper.CreateRelation(
		Subject{Type: "team", ID: "engineering", Relation: "member"},
		"reader",
		Resource{Type: "post", ID: "1"},
	); err != nil {
		logrus.Fatal(err)
	}

	// time.Sleep(5 * time.Second)

	if allowed, err := helper.CheckPermissionConsistent(
		Resource{Type: "post", ID: "1"},
		Subject{Type: "user", ID: "dries"},
		"read",
	); err == nil && allowed {
		logrus.Info("Dries has read permission on first post")
	} else {
		logrus.Error("Expected Dries to have read permission on first post")
	}

	if allowed, err := helper.CheckPermission(
		Resource{Type: "post", ID: "1"},
		Subject{Type: "user", ID: "emilia"},
		"read",
	); err == nil && allowed {
		logrus.Info("Emilia has read permission on first post")
	} else {
		logrus.Error("Expected Emilia to have read permission on first post")
	}

	if allowed, err := helper.CheckPermissionConsistent(
		Resource{Type: "post", ID: "2"},
		Subject{Type: "user", ID: "emilia"},
		"read",
	); err == nil && !allowed {
		logrus.Info("Emilia has no read permission on second post")
	} else {
		logrus.Error("Expected Emilia to have no read permission on second post")
	}
}

func NewSpiceDBHelper(endpoint, token string) (*SpiceDBHelper, error) {
	client, err := authzed.NewClient(
		endpoint,
		grpcutil.WithInsecureBearerToken(token),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	return &SpiceDBHelper{
		client: client,
	}, err
}

type SpiceDBHelper struct {
	client *authzed.Client
}

type Resource struct {
	Type string
	ID   string
}

type Subject struct {
	Type     string
	ID       string
	Relation string
}

func (s *SpiceDBHelper) CreateRelation(subject Subject, relation string, resource Resource) error {
	request := &pb.WriteRelationshipsRequest{Updates: []*pb.RelationshipUpdate{
		{
			Operation: pb.RelationshipUpdate_OPERATION_TOUCH,
			Relationship: &pb.Relationship{
				Resource: &pb.ObjectReference{
					ObjectType: resource.Type,
					ObjectId:   resource.ID,
				},
				Relation: relation,
				Subject: &pb.SubjectReference{
					Object: &pb.ObjectReference{
						ObjectType: subject.Type,
						ObjectId:   subject.ID,
					},
					OptionalRelation: subject.Relation,
				},
			},
		},
	}}

	resp, err := s.client.WriteRelationships(context.Background(), request)
	if err == nil {
		logrus.Trace(resp.WrittenAt.Token)
	}
	if err != nil {
		logrus.Error(err, resp)
	}

	return err
}

func (s *SpiceDBHelper) CheckPermission(resource Resource, subject Subject, permission string) (bool, error) {
	return s.checkPermission(resource, subject, permission, nil)
}
func (s *SpiceDBHelper) CheckPermissionConsistent(resource Resource, subject Subject, permission string) (bool, error) {
	return s.checkPermission(resource, subject, permission, &pb.Consistency{
		Requirement: &pb.Consistency_FullyConsistent{FullyConsistent: true},
	})
}

func (s *SpiceDBHelper) checkPermission(resource Resource, subject Subject, permission string, consitency *pb.Consistency) (bool, error) {
	resp, err := s.client.CheckPermission(context.Background(), &pb.CheckPermissionRequest{
		Resource: &pb.ObjectReference{
			ObjectType: resource.Type,
			ObjectId:   resource.ID,
		},
		Permission: permission,
		Subject: &pb.SubjectReference{Object: &pb.ObjectReference{
			ObjectType: subject.Type,
			ObjectId:   subject.ID,
		}},
		Consistency: consitency,
	})
	if err != nil {
		return false, err
	}
	return resp.Permissionship == pb.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION, nil
}

func (s *SpiceDBHelper) CreateSchema() error {
	_, err := s.client.WriteSchema(context.Background(), &pb.WriteSchemaRequest{Schema: schema})
	return err
}
