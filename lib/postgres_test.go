package lib

import (
	"context"
	"fmt"
	"github.com/deso-protocol/core/migrate"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"github.com/go-pg/pg/v10"
	migrations "github.com/robinjoseph08/go-pg-migrations/v3"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Set to true if you don't want to use the postgres testing framework.
const DISABLE_POSTGRES_DOCKER_API = false

// Config variables for spawning the postgres container.
const CONTAINER_NAME = "test_postgresql"
const LOCAL_PORT = "5433"
const REMOTE_PORT = "5432"
const POSTGRES_USER = "postgres"
const POSTGRES_PASSWORD = "postgres"
const POSTGRES_DB = "test_postgres"

// Configs for connecting to postgres.
const MAX_CONNECTION_ATTEMPTS = 20
const ATTEMPT_TIMEOUT = 3 * time.Second

// get a random temporary directory.
func getDirectory(t *testing.T) string {
	require := require.New(t)
	dbDir, err := ioutil.TempDir("", "badgerdb")
	if err != nil {
		require.NoError(err)
	}
	return dbDir
}

func RunTestWithBadgerAndPostgresOptimized(t *testing.T, testFunction func(t *testing.T, postgres *Postgres)) {
	var postgres *Postgres
	postgresChannel := make(chan struct{})
	go func() {
		postgres = InitializeTestPostgresInstance(t)
		postgresChannel <- struct{}{}
	}()
	testFunction(t, nil)
	<-postgresChannel
	testFunction(t, postgres)
}

// InitializeTestPostgresInstance, similarly to NewLowDifficultyBlockchain, is intended to help in creating unit tests.
// It abstracts away initializing a Postgres database, so that you don't need to play around with creating and maintaining
// a test pg db. To achieve this, we will spawn a test postgres container using the Docker API, connect to it, and return
// the connection. Because spawning a container is costly, we only do it once, and then just connect to it across different
// invocations of this function.
func InitializeTestPostgresInstance(t *testing.T) *Postgres {
	require := require.New(t)
	_ = require

	// Return nil if we don't want postgres testing.
	if DISABLE_POSTGRES_DOCKER_API {
		return nil
	}

	// Check if test postgres container is running.
	pgContainers := getPostgresqlContainers(t)
	var pgContainer *types.Container
	if len(pgContainers) > 0 {
	out:
		// We found at least one container that matches our CONTAINER_NAME. We will make sure it has the correct port
		// forwarding configured. This is more of a sanity-check.
		for _, cont := range pgContainers {
			for _, port := range cont.Ports {
				if strconv.FormatUint(uint64(port.PrivatePort), 10) == REMOTE_PORT &&
					strconv.FormatUint(uint64(port.PublicPort), 10) == LOCAL_PORT {
					pgContainer = cont
					break out
				}
			}
		}
	}

	// If we found a postgres testing container, we will try to connect to it. Otherwise, we will spawn a new container.
	var postgres *Postgres
	if pgContainer != nil {
		postgres = connectTestPostgresInstance(t)
		postgres.containerId = pgContainer.ID
	} else {
		postgres = startTestPostgresContainerAndConnect(t)
	}
	// Completely clear the database.
	err := postgres.resetDatabase()
	require.NoError(err)

	// Create all the tables using migrations.
	migrate.LoadMigrations()
	err = migrations.Run(postgres.db, "migrate", []string{"", "migrate"})
	require.NoError(err)
	return postgres
}

// We will try to connect to the postgres instance that is running in our test container. Sometimes, we might not be able
// to connect on the first try. This happens especially when we're spawning a new container. To solve this, this function
// attempts forming a connection a couple of times.
func connectTestPostgresInstance(t *testing.T) *Postgres {
	require := require.New(t)
	_ = require

	// Get connection URL and options.
	postgresUrl := fmt.Sprintf("postgresql://%v:%v@0.0.0.0:%v/%v?sslmode=disable",
		POSTGRES_USER,
		POSTGRES_PASSWORD,
		LOCAL_PORT,
		POSTGRES_DB,
	)
	options, err := pg.ParseURL(postgresUrl)
	require.NoError(err)
	// Create a connection.
	db := pg.Connect(options)

	// Now, postgres might be connected, but it might not be available. To test for this, we will ping the db.
	var ii int
	for ii = 0; ii < MAX_CONNECTION_ATTEMPTS; ii++ {
		if err = db.Ping(context.Background()); err != nil {
			eofString := ""
			if err.Error() == "EOF" {
				eofString = "(Note: it's normal to get a bunch of EOFs. If connection fails after many EOFs, " +
					"try increasing maxConnectionAttempts)"
			}
			fmt.Printf("Pinging postgres attempt (%v/%v) err: %v %v\n", ii, MAX_CONNECTION_ATTEMPTS, err, eofString)
		} else {
			break
		}
		time.Sleep(ATTEMPT_TIMEOUT)
	}
	if ii == MAX_CONNECTION_ATTEMPTS {
		t.Fatalf("Failed connecting to postgres in %v attempts", ii)
	}

	return &Postgres{
		db: db,
	}
}

// startTestPostgresContainerAndConnect will spawn a postgres container with a volume mapped to some random directory,
// and port-forwarded 0.0.0.0 : LOCAL_PORT <-> remote : REMOTE_PORT where REMOTE_PORT coincides with the postgres daemon.
func startTestPostgresContainerAndConnect(t *testing.T) *Postgres {
	require := require.New(t)
	_ = require

	// Get random directory.
	postgresDir := getDirectory(t)

	// Create a docker client.
	cli, err := client.NewClientWithOpts(client.FromEnv)
	require.NoError(err)

	// Volumes map will mount remote's postgres directory to our host's random directory.
	volumesMap := make(map[string]struct{})
	volumesMap["/var/lib/postgresql/data"] = struct{}{}

	// Configure port-forwarding.
	ports := make(nat.PortSet)
	firstPort, err := nat.NewPort("tcp", REMOTE_PORT)
	require.NoError(err)
	ports[firstPort] = struct{}{}

	// Configure postgresDb environmental variables.
	env := []string{
		"POSTGRES_USER=" + POSTGRES_USER,
		"POSTGRES_PASSWORD=" + POSTGRES_PASSWORD,
		"POSTGRES_DB=" + POSTGRES_DB,
	}

	// Get container's config.
	config := &container.Config{
		Hostname:     "0.0.0.0",
		Env:          env,
		Volumes:      volumesMap,
		Image:        "postgres",
		ExposedPorts: ports,
	}
	// Get host's config.
	hostConfig := &container.HostConfig{
		Binds: []string{postgresDir + ":/var/lib/postgresql/data"},
		PortBindings: nat.PortMap{
			REMOTE_PORT + "/tcp": []nat.PortBinding{{
				HostIP:   "0.0.0.0",
				HostPort: LOCAL_PORT,
			}},
		},
	}
	// Get network config.
	networkConfig := &network.NetworkingConfig{}

	// Spawn the test postgres db container.
	postgresContainer, err := cli.ContainerCreate(
		context.Background(),
		config,
		hostConfig,
		networkConfig,
		nil,
		CONTAINER_NAME,
	)
	containerId := postgresContainer.ID
	require.NoError(err)

	// Now start the container.
	err = cli.ContainerStart(
		context.Background(),
		containerId,
		types.ContainerStartOptions{},
	)
	require.NoError(err)

	// Finally, connect to the container's postgres db.
	postgres := connectTestPostgresInstance(t)
	postgres.directory = postgresDir
	postgres.containerId = containerId
	return postgres
}

// getPostgresqlContainers will look for all containers that are named CONTAINER_NAME.
func getPostgresqlContainers(t *testing.T) []*types.Container {
	require := require.New(t)
	cli, err := client.NewClientWithOpts(client.FromEnv)
	require.NoError(err)

	containers, err := cli.ContainerList(context.Background(), types.ContainerListOptions{All: true})
	require.NoError(err)

	var postgresContainers []*types.Container
	for _, cont := range containers {
		for _, name := range cont.Names {
			if strings.Contains(name, CONTAINER_NAME) {
				postgresContainers = append(postgresContainers, &cont)
				break
			}
		}
	}
	return postgresContainers
}

// killAllPostgresContainers removes all containers that have the name CONTAINER_NAME.
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

func TestPostgresContainerSpawnAndKill(t *testing.T) {
	require := require.New(t)

	postgres := InitializeTestPostgresInstance(t)
	cli, err := client.NewClientWithOpts(client.FromEnv)
	require.NoError(err)
	containers, err := cli.ContainerList(context.Background(), types.ContainerListOptions{})
	fmt.Println(containers)
	postgresContainers := getPostgresqlContainers(t)
	fmt.Println(postgresContainers)
	require.NoError(postgres.forceKillContainer())
}

func TestParsePostgresURI(t *testing.T) {
	require := require.New(t)

	// No password.
	pgURI := "postgresql://testUser@localhost:5432/testDatabase"
	pgOptions := ParsePostgresURI(pgURI)
	require.Equal(pgOptions.Addr, "localhost:5432")
	require.Equal(pgOptions.User, "testUser")
	require.Equal(pgOptions.Database, "testDatabase")
	require.Equal(pgOptions.Password, "")

	// With password.
	pgURI = "postgresql://testUser:testPassword@postgres:5432/testDatabase"
	pgOptions = ParsePostgresURI(pgURI)
	require.Equal(pgOptions.Addr, "postgres:5432")
	require.Equal(pgOptions.User, "testUser")
	require.Equal(pgOptions.Database, "testDatabase")
	require.Equal(pgOptions.Password, "testPassword")
}
