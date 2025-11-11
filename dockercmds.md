Run the Go test suite in Docker (uses `.env` + `.env.test` for config):
docker compose up --build tests      # stream test output until completion
docker compose run --rm tests        # one-off test run without logs follow

The Docker daemon (background service):
sudo systemctl start docker     # start Docker service
sudo systemctl stop docker      # stop Docker service
sudo systemctl restart docker   # restart (after config change)
sudo systemctl status docker    # check if it's running

Containers (running apps):
docker run -d --name myapp nginx    # run a container
docker ps                           # see running containers
docker ps -a                        # See all containers (including stopped)
docker stop myapp                   # Stop a running container
docker start myapp                  # Start a stopped container again
docker rm myapp                     # Remove a container
docker container prune              # To remove all stopped containers

.yml
docker compose up          # start all services
docker compose down        # stop and remove
docker compose ps          # see running services
docker compose logs -f     # follow logs

Quick mental model
You want to…	            Command
See what’s running	        docker ps
Stop something	            docker stop <name>
Delete it	                docker rm <name>
See logs	                docker logs <name>
Build image	                docker build -t <name> .
Compose up/down	            docker compose up / down
