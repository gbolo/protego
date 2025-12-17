# Fake Data Generator for Protego

This tool generates fake test data for the Protego server using the [gofakeit](https://github.com/brianvoe/gofakeit) library.

## Features

- Creates a configurable number of users with realistic fake data
- Uses fake emails as user IDs
- Generates secure random passwords
- Creates realistic user descriptions (Name + Job Title)
- Randomly assigns TTL values (6h, 1d, 2d, or 7d)
- 20% of users get `acl_allow_all` enabled
- 30% of users get random allowed hosts
- Performs 1-3 challenges for 80% of the created users with random IP addresses

## Installation

```bash
cd testdata/fakedata
go mod download
go build -o fakedata
```

## Usage

### Basic Usage

```bash
# Run with defaults (10 users, localhost:8080)
./fakedata

# Specify number of users
./fakedata -users 50
```

### Configuration Options

#### Command Line Flags

```bash
./fakedata -url http://protego.example.com:8080 \
           -admin-secret mySecretKey \
           -users 100
```

#### Environment Variables

```bash
export PROTEGO_URL=http://localhost:8080
export PROTEGO_ADMIN_SECRET=changeme
./fakedata -users 25
```

### Configuration Parameters

| Flag | Environment Variable | Default | Description |
|------|---------------------|---------|-------------|
| `-url` | `PROTEGO_URL` | `http://localhost:8080` | Base URL of the Protego server |
| `-admin-secret` | `PROTEGO_ADMIN_SECRET` | `changeme` | Admin secret for API authentication |
| `-users` | - | `10` | Number of users to create |

## Example Output

```
Starting fake data generation...
Protego URL: http://localhost:8080
Number of users to create: 10

=== Creating Users ===
✅ Created user: john.doe@example.com (John Doe - Software Engineer)
✅ Created user: jane.smith@example.com (Jane Smith - Product Manager)
...

=== Performing Challenges for 8 users (80%) ===
✅ Challenge successful for user john.doe@example.com from IP 192.168.1.100
✅ Challenge successful for user john.doe@example.com from IP 10.0.0.5
✅ Challenge successful for user jane.smith@example.com from IP 172.16.0.10
...

=== Summary ===
Total users created: 10
Users with challenges: 8
Total challenge attempts: 18
Successful challenges (IPs whitelisted): 18
✅ Fake data generation complete!
```

## Generated User Data

Each user is created with:

- **ID**: Random email address (e.g., `john.doe@example.com`)
- **Secret**: 16-character password with uppercase, lowercase, numbers, and special characters
- **Description**: Random name and job title (e.g., "Alice Johnson - DevOps Engineer")
- **Enabled**: Always `true`
- **ACL Allow All**: 20% chance of being `true`
- **ACL Allowed Hosts**: 30% chance of having 1-3 random domain names
- **TTL Minutes**: Randomly selected from: 360 (6h), 1440 (1d), 2880 (2d), or 10080 (7d)

## Challenge Behavior

- 80% of created users will have challenges performed
- Each selected user gets 1-3 challenges with random IP addresses
- Small 100ms delay between challenges to avoid overwhelming the server
- Uses random IPv4 addresses for each challenge

## Use Cases

- **Testing**: Quickly populate a test instance with realistic data
- **Development**: Create a development environment with sample users
- **Load Testing**: Generate many users and challenges to test server performance
- **Demo**: Populate a demo instance for presentations

## Requirements

- Go 1.21 or higher
- Running Protego server instance
- Valid admin secret for the server
