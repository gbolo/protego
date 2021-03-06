package server

import (
	_ "expvar"
	"fmt"
	"net/http"
	_ "net/http/pprof"

	"github.com/gbolo/protego/asset"
	_ "github.com/gbolo/protego/docs"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/spf13/viper"
	httpSwagger "github.com/swaggo/http-swagger"
)

const (
	// APIVersion defines the compatibility version of the API and is appended to each API route
	APIVersion     = "1"
	endpointFormat = "/api/v%s/%s"
)

// getEndpoint returns a properly formatted API endpoint
func getEndpoint(suffix string) string {
	return fmt.Sprintf(endpointFormat, APIVersion, suffix)
}

// Route defines a route passed to our mux
type Route struct {
	Name        string
	Method      string
	Pattern     string
	HandlerFunc http.HandlerFunc
}

// Routes holds a list of Routes
type Routes []Route

// all defined server endpoints
var routes = Routes{

	// API endpoints
	Route{
		"Version",
		"GET",
		getEndpoint("version"),
		handlerVersion,
	},

	Route{
		"Authorize",
		"GET",
		getEndpoint("authorize"),
		handlerAuthorize,
	},

	Route{
		"Challenge",
		"POST",
		getEndpoint("challenge"),
		handlerChallenge,
	},

	Route{
		"UserAdd",
		"POST",
		getEndpoint("user"),
		handlerUserAdd,
	},

	Route{
		"UserModify",
		"PUT",
		getEndpoint("user/{user-id}"),
		handlerUserUpdate,
	},

	Route{
		"UserRemove",
		"DELETE",
		getEndpoint("user/{user-id}"),
		handlerUserDelete,
	},

	Route{
		"UserGet",
		"GET",
		getEndpoint("user/{user-id}"),
		handlerUserGet,
	},

	Route{
		"UsersGetAll",
		"GET",
		getEndpoint("user"),
		handlerUserGetAll,
	},
}

func newRouter() *mux.Router {

	router := mux.NewRouter().StrictSlash(true)
	for _, route := range routes {

		// add compression support to handler if enabled
		var handler http.Handler
		handler = route.HandlerFunc
		if viper.GetBool("server.compression") {
			handler = handlers.CompressHandler(route.HandlerFunc)
		}

		// add routes to mux
		router.
			Methods(route.Method).
			Path(route.Pattern).
			Name(route.Name).
			Handler(handler)
	}

	// add swagger UI
	router.Methods("GET").Path("/swagger").HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// redirect to /swagger/index.html which is provided by httpSwagger.WrapHandler
		http.Redirect(w, req, "/swagger/index.html", 301)
	})
	router.Methods("GET").PathPrefix("/swagger").Handler(httpSwagger.WrapHandler)

	// add route for pprof if enabled
	if viper.GetBool("server.enable_profiler") {
		log.Warning("profiler is enabled on endpoint /debug/")
		router.Methods("GET").PathPrefix("/debug/").Handler(http.DefaultServeMux)
	}

	// add embedded assets
	handlerStatic := http.StripPrefix("/", http.FileServer(asset.Assets))
	// add compression support to handler if enabled
	if viper.GetBool("server.compression") {
		handlerStatic = handlers.CompressHandler(handlerStatic)
	}

	router.
		Methods("GET").
		PathPrefix("/").
		Handler(handlerStatic)

	return router
}
