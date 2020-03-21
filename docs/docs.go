// GENERATED BY THE COMMAND ABOVE; DO NOT EDIT
// This file was generated by swaggo/swag at
// 2020-03-21 00:54:38.154702039 -0400 EDT m=+0.033030517

package docs

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/alecthomas/template"
	"github.com/swaggo/swag"
)

var doc = `{
    "schemes": {{ marshal .Schemes }},
    "swagger": "2.0",
    "info": {
        "description": "{{.Description}}",
        "title": "{{.Title}}",
        "termsOfService": "http://swagger.io/terms/",
        "contact": {
            "name": "API Support",
            "email": "gbolo@linuxctl.com"
        },
        "license": {
            "name": "MIT",
            "url": "https://github.com/gbolo/protego/blob/master/LICENSE"
        },
        "version": "{{.Version}}"
    },
    "host": "{{.Host}}",
    "basePath": "{{.BasePath}}",
    "paths": {
        "/authorize": {
            "get": {
                "description": "Configure NGINX auth_request to this endpoint",
                "tags": [
                    "Authorization"
                ],
                "summary": "NGINX auth_request destination",
                "parameters": [
                    {
                        "type": "string",
                        "description": "IP address of the user",
                        "name": "X-Real-IP",
                        "in": "header",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "the host (FQDN) the user is making a request to",
                        "name": "Host",
                        "in": "header"
                    }
                ],
                "responses": {
                    "200": {
                        "description": "access granted"
                    },
                    "401": {
                        "description": "unauthorized - user IP is unknown or not permitted to access this host"
                    }
                }
            }
        },
        "/challenge": {
            "post": {
                "description": "A user must successfully POST to this URL in order for their IP address to be granted access",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Authorization"
                ],
                "summary": "Challenge used to authorize an IP address for access",
                "parameters": [
                    {
                        "type": "string",
                        "description": "IP address of the user",
                        "name": "X-Real-IP",
                        "in": "header",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "Secret that was given to/by the user",
                        "name": "User-Secret",
                        "in": "header",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "challenge was accepted: the value of X-Real-IP has been granted an ACL"
                    },
                    "400": {
                        "description": "bad request: X-Real-IP is not set"
                    },
                    "401": {
                        "description": "unauthorized: the user secret is incorrect or the user is disabled"
                    },
                    "500": {
                        "description": "server could not process the request"
                    }
                }
            }
        },
        "/user": {
            "post": {
                "description": "add by json user",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "User"
                ],
                "summary": "Add a new User",
                "parameters": [
                    {
                        "type": "string",
                        "description": "Admin Secret",
                        "name": "Admin-Secret",
                        "in": "header",
                        "required": true
                    },
                    {
                        "description": "Add User",
                        "name": "user",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/server.addUser"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/server.getUser"
                        }
                    }
                }
            }
        },
        "/user/{id}": {
            "get": {
                "description": "get User by ID",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "User"
                ],
                "summary": "Retrieve a User based on provided ID",
                "parameters": [
                    {
                        "type": "string",
                        "description": "Admin Secret",
                        "name": "ADMIN-SECRET",
                        "in": "header",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "User ID",
                        "name": "id",
                        "in": "path",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/server.getUser"
                        }
                    }
                }
            },
            "put": {
                "description": "update by json user",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "User"
                ],
                "summary": "Update an existing User",
                "parameters": [
                    {
                        "type": "string",
                        "description": "Admin Secret",
                        "name": "Admin-Secret",
                        "in": "header",
                        "required": true
                    },
                    {
                        "description": "Update User",
                        "name": "user",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/server.modifyUser"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/server.getUser"
                        }
                    }
                }
            },
            "delete": {
                "description": "remove a User by ID",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "User"
                ],
                "summary": "Remove a User based on provided ID",
                "parameters": [
                    {
                        "type": "string",
                        "description": "Admin Secret",
                        "name": "ADMIN-SECRET",
                        "in": "header",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "User ID",
                        "name": "id",
                        "in": "path",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/server.getUser"
                        }
                    }
                }
            }
        },
        "/version": {
            "get": {
                "description": "Retrieve the version information of this Protego server",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Version"
                ],
                "summary": "Version information",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/server.version"
                        }
                    }
                }
            }
        }
    },
    "definitions": {
        "server.addUser": {
            "type": "object",
            "properties": {
                "acl_allow_all": {
                    "description": "Determines if this User is allowed to access ALL resources",
                    "type": "boolean",
                    "example": false
                },
                "acl_allowed_hosts": {
                    "description": "A list of hosts (FQDN) this User is allowed to access",
                    "type": "array",
                    "items": {
                        "type": "string"
                    },
                    "example": [
                        "git.example.com",
                        "wiki.example.com"
                    ]
                },
                "description": {
                    "description": "A brief description of this User",
                    "type": "string",
                    "example": "Cloud Strife"
                },
                "dns_names": {
                    "description": "A list of DNS names that resolve this User's IPs which get whitelisted automatically without a challenge.",
                    "type": "array",
                    "items": {
                        "type": "string"
                    },
                    "example": [
                        "myhome.no-ip.info"
                    ]
                },
                "enabled": {
                    "description": "Determines if this User is enabled",
                    "type": "boolean",
                    "example": true
                },
                "secret": {
                    "description": "This secret is used as a challenge to whitelist a User's IP",
                    "type": "string",
                    "example": "supersecret"
                },
                "ttl_minutes": {
                    "description": "Represents the number of minutes this User's IP is whitelisted for after a successful challenge",
                    "type": "integer",
                    "example": 60
                }
            }
        },
        "server.getUser": {
            "type": "object",
            "properties": {
                "acl_allow_all": {
                    "description": "Determines if this User is allowed to access ALL resources",
                    "type": "boolean",
                    "example": false
                },
                "acl_allowed_hosts": {
                    "description": "A list of hosts (FQDN) this User is allowed to access",
                    "type": "array",
                    "items": {
                        "type": "string"
                    },
                    "example": [
                        "git.example.com",
                        "wiki.example.com"
                    ]
                },
                "description": {
                    "description": "A brief description of this User",
                    "type": "string",
                    "example": "Cloud Strife"
                },
                "dns_names": {
                    "description": "A list of DNS names that resolve this User's IPs which get whitelisted automatically without a challenge.",
                    "type": "array",
                    "items": {
                        "type": "string"
                    },
                    "example": [
                        "myhome.no-ip.info"
                    ]
                },
                "enabled": {
                    "description": "Determines if this User is enabled",
                    "type": "boolean",
                    "example": true
                },
                "id": {
                    "description": "A unique identifier for this User",
                    "type": "string",
                    "example": "5e8848"
                },
                "ttl_minutes": {
                    "description": "Represents the number of minutes this User's IP is whitelisted for after a successful challenge",
                    "type": "integer",
                    "example": 60
                }
            }
        },
        "server.modifyUser": {
            "type": "object",
            "properties": {
                "acl_allow_all": {
                    "description": "Determines if this User is allowed to access ALL resources",
                    "type": "boolean",
                    "example": false
                },
                "acl_allowed_hosts": {
                    "description": "A list of hosts (FQDN) this User is allowed to access",
                    "type": "array",
                    "items": {
                        "type": "string"
                    },
                    "example": [
                        "git.example.com",
                        "wiki.example.com"
                    ]
                },
                "description": {
                    "description": "A brief description of this User",
                    "type": "string",
                    "example": "Cloud Strife"
                },
                "dns_names": {
                    "description": "A list of DNS names that resolve this User's IPs which get whitelisted automatically without a challenge.",
                    "type": "array",
                    "items": {
                        "type": "string"
                    },
                    "example": [
                        "myhome.no-ip.info"
                    ]
                },
                "enabled": {
                    "description": "Determines if this User is enabled",
                    "type": "boolean",
                    "example": true
                },
                "ttl_minutes": {
                    "description": "Represents the number of minutes this User's IP is whitelisted for after a successful challenge",
                    "type": "integer",
                    "example": 60
                }
            }
        },
        "server.version": {
            "type": "object",
            "properties": {
                "build_ref": {
                    "type": "string",
                    "example": "git-30b8019"
                },
                "version": {
                    "type": "string",
                    "example": "v1.0"
                }
            }
        }
    }
}`

type swaggerInfo struct {
	Version     string
	Host        string
	BasePath    string
	Schemes     []string
	Title       string
	Description string
}

// SwaggerInfo holds exported Swagger Info so clients can modify it
var SwaggerInfo = swaggerInfo{
	Version:     "1.0",
	Host:        "",
	BasePath:    "/api/v1",
	Schemes:     []string{},
	Title:       "Protego - REST API",
	Description: "Swagger API for Protego - https://github.com/gbolo/protego",
}

type s struct{}

func (s *s) ReadDoc() string {
	sInfo := SwaggerInfo
	sInfo.Description = strings.Replace(sInfo.Description, "\n", "\\n", -1)

	t, err := template.New("swagger_info").Funcs(template.FuncMap{
		"marshal": func(v interface{}) string {
			a, _ := json.Marshal(v)
			return string(a)
		},
	}).Parse(doc)
	if err != nil {
		return doc
	}

	var tpl bytes.Buffer
	if err := t.Execute(&tpl, sInfo); err != nil {
		return doc
	}

	return tpl.String()
}

func init() {
	swag.Register(swag.Name, &s{})
}
