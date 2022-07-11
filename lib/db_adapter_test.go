package lib

import (
	"context"
	"fmt"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"github.com/go-pg/pg/v10"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"
)

// get a random temporary directory.
func getDirectory(t *testing.T) string {
	require := require.New(t)
	dbDir, err := ioutil.TempDir("", "badgerdb")
	if err != nil {
		require.NoError(err)
	}
	return dbDir
}

func (postgres *Postgres) resetDatabase() error {
	res, err := postgres.db.Exec("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
	if err != nil {
		return errors.Wrapf(err, "DeletePostgresDatabase: Problem executing the query")
	}
	glog.Infof(CLog(Blue, fmt.Sprintf("DeletePostgresDatabase: Got res %v", res)))
	return nil
}

func initializeTestPostgresInstance(t *testing.T) *Postgres {
	require := require.New(t)
	_ = require

	// Check if test postgres container is running.
	pgContainers := getPostgresqlContainers(t)
	var pgContainer *types.Container
	if len(pgContainers) > 0 {
	out:
		for _, cont := range pgContainers {
			for _, port := range cont.Ports {
				if port.PrivatePort == uint16(5432) && port.PublicPort == uint16(5433) {
					pgContainer = cont
					break out
				}
			}
		}
	}

	var postgres *Postgres
	if pgContainer != nil {
		postgres = connectTestPostgresInstance(t)
		postgres.containerId = pgContainer.ID
	} else {
		postgres = startTestPostgresContainerAndConnect(t)
	}
	err := postgres.resetDatabase()
	require.NoError(err)
	return postgres
}

func connectTestPostgresInstance(t *testing.T) *Postgres {
	require := require.New(t)
	_ = require
	maxConnectionAttempts := 20
	attemptTimeout := 3 * time.Second

	postgresUrl := "postgresql://postgres:postgres@0.0.0.0:5433/postgres?sslmode=disable"
	options, err := pg.ParseURL(postgresUrl)
	require.NoError(err)

	db := pg.Connect(options)

	var ii int
	for ii = 0; ii < maxConnectionAttempts; ii++ {
		if err = db.Ping(context.Background()); err != nil {
			eofString := ""
			if err.Error() == "EOF" {
				eofString = "(Note: it's normal to get a bunch of EOFs. If connection fails after many EOFs, " +
					"try increasing maxConnectionAttempts)"
			}
			fmt.Printf("Pinging postgres attempt (%v/%v) err: %v %v\n", ii, maxConnectionAttempts, err, eofString)
		} else {
			break
		}
		time.Sleep(attemptTimeout)
	}
	if ii == maxConnectionAttempts {
		t.Fatalf("Failed connecting to postgres in %v attempts", ii)
	}

	return &Postgres{
		db: db,
	}
}

func startTestPostgresContainerAndConnect(t *testing.T) *Postgres {
	require := require.New(t)
	_ = require

	postgresDir := getDirectory(t)
	cli, err := client.NewClientWithOpts(client.FromEnv)
	require.NoError(err)

	volumesMap := make(map[string]struct{})
	volumesMap["/var/lib/postgresql/data"] = struct{}{}

	ports := make(nat.PortSet)
	firstPort, err := nat.NewPort("tcp", "5432")
	require.NoError(err)
	ports[firstPort] = struct{}{}

	config := &container.Config{
		Hostname:     "0.0.0.0",
		Env:          []string{"POSTGRES_USER=postgres", "POSTGRES_PASSWORD=postgres", "POSTGRES_DB=postgres"},
		Volumes:      volumesMap,
		Image:        "postgres",
		ExposedPorts: ports,
	}
	hostConfig := &container.HostConfig{
		Binds: []string{postgresDir + ":/var/lib/postgresql/data"},
		PortBindings: nat.PortMap{
			"5432/tcp": []nat.PortBinding{{
				HostIP:   "0.0.0.0",
				HostPort: "5433",
			}},
		},
	}
	networkConfig := &network.NetworkingConfig{}

	postgresContainer, err := cli.ContainerCreate(
		context.Background(),
		config,
		hostConfig,
		networkConfig,
		nil,
		"postgresql",
	)
	containerId := postgresContainer.ID
	require.NoError(err)

	err = cli.ContainerStart(
		context.Background(),
		containerId,
		types.ContainerStartOptions{},
	)
	require.NoError(err)

	postgres := connectTestPostgresInstance(t)
	postgres.directory = postgresDir
	postgres.containerId = containerId
	return postgres
}

func (postgres *Postgres) forceKillContainer() error {
	if postgres.containerId == "" {
		return fmt.Errorf("forceKillContainer: container Id is empty. This function only works for dockerized postgres")
	}

	err := postgres.db.Close()
	if err != nil {
		return errors.Wrapf(err, "forceKillContainer: Problem closing postgres db")
	}

	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return errors.Wrapf(err, "forceKillContainer: Problem creating new docker client")
	}

	removeOptions := types.ContainerRemoveOptions{
		Force: true,
	}
	err = cli.ContainerRemove(context.Background(), postgres.containerId, removeOptions)
	if err != nil {
		return errors.Wrapf(err, "forceKillContainer: Problem removing postgres container")
	}

	if postgres.directory == "" {
		err = os.RemoveAll(postgres.directory)
		if err != nil {
			return errors.Wrapf(err, "forceKillContainer: Problem removing postgres directory")
		}
	}
	return nil
}

func getPostgresqlContainers(t *testing.T) []*types.Container {
	require := require.New(t)
	cli, err := client.NewClientWithOpts(client.FromEnv)
	require.NoError(err)

	containers, err := cli.ContainerList(context.Background(), types.ContainerListOptions{All: true})
	require.NoError(err)

	var postgresContainers []*types.Container
	for _, cont := range containers {
		for _, name := range cont.Names {
			if strings.Contains(name, "postgresql") {
				postgresContainers = append(postgresContainers, &cont)
				break
			}
		}
	}
	return postgresContainers
}

func killAllPostgresContainers(t *testing.T) {
	require := require.New(t)
	cli, err := client.NewClientWithOpts(client.FromEnv)
	require.NoError(err)

	removeOptions := types.ContainerRemoveOptions{
		Force: true,
	}

	postgresContainers := getPostgresqlContainers(t)
	for _, cont := range postgresContainers {
		err = cli.ContainerRemove(context.Background(), cont.ID, removeOptions)
		require.NoError(err)
	}
}

func TestKillAllPostgresContainers(t *testing.T) {
	killAllPostgresContainers(t)
}

func TestPostgresReset(t *testing.T) {
	require := require.New(t)

	postgres := initializeTestPostgresInstance(t)

	res, err := postgres.db.Exec("SELECT * FROM pg_catalog.pg_tables WHERE " +
		"schemaname != 'pg_catalog' AND schemaname != 'information_schema';")
	require.NoError(err)
	fmt.Println(res.RowsReturned())
	err = postgres.resetDatabase()
	require.NoError(err)
	res, err = postgres.db.Exec("SELECT * FROM pg_catalog.pg_tables WHERE " +
		"schemaname != 'pg_catalog' AND schemaname != 'information_schema';")
	require.NoError(err)
	fmt.Println(res.RowsReturned())

	cli, err := client.NewClientWithOpts(client.FromEnv)
	require.NoError(err)
	containers, err := cli.ContainerList(context.Background(), types.ContainerListOptions{})
	fmt.Println(containers)
	postgresContainers := getPostgresqlContainers(t)
	fmt.Println(postgresContainers)
	require.NoError(postgres.forceKillContainer())
}

func printContainers(t *testing.T, cli *client.Client) {
	require := require.New(t)

	containers, err := cli.ContainerList(context.Background(), types.ContainerListOptions{})
	require.NoError(err)

	for _, container := range containers {
		fmt.Printf("%s %s\n", container.ID[:10], container.Image)
	}
}
