package main

import (
  "github.com/gin-gonic/gin"
  "github.com/go-playground/validator/v10"
  "github.com/satori/go.uuid"
  _ "github.com/lib/pq"
  "github.com/go-xorm/xorm"
  "encoding/json"
	"io/ioutil"
	"fmt"
	"net/http"
  "crypto/md5"
  "io"
)

var validate *validator.Validate
var engine *xorm.Engine

const (
	host = "192.168.1.11"
	port = 5432
	user = "jacky"
	password = "jacky_123456"
	dbName="customer"
)

type Password struct {
  Id string `json:"id" sql:",type:uuid"`
  Mobile string `json:"moblie"`
  Password string `json:"-"`
}

func errHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				c.JSON(http.StatusOK, gin.H{
      	        "status" : 0,
                "message" : fmt.Errorf("%v", err).Error(),
        })

				return
			}
		}()
		c.Next()
	}
}

func responseHandler() gin.HandlerFunc {
    return func(c *gin.Context) {
        c.Next()
        if c.Writer.Written() {
            return
        }

        params := c.Keys
        if len(params) == 0 {
            return
        }
      	params["status"] = 1
      	params["message"] = "success"
        c.JSON(http.StatusOK, params)
    }
}



func validateCustomerStruct(customer Password) {
  err := validate.Struct(customer)
  	if err != nil {
      if _, ok := err.(*validator.InvalidValidationError); ok {
        panic(err)
        return
      }

      for _, err := range err.(validator.ValidationErrors) {
        panic(err.Field() + " must be " + err.ActualTag() + " " + err.Param())
      }
      return
  	}
}

func md5String(str string) string {
    w := md5.New()
    io.WriteString(w, str)
    md5str := fmt.Sprintf("%x", w.Sum(nil))
    return md5str
}

func main() {
  psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",host,port,user,password,dbName)
  engine, _ = xorm.NewEngine("postgres", psqlInfo)

  //gin.SetMode(gin.ReleaseMode)
  router := gin.Default()
	router.Use(errHandler())
	router.Use(responseHandler())
  validate = validator.New()

	router.POST("/customer", func(c *gin.Context) {
    //body, _ := ioutil.ReadAll(c.Request.Body)
    var pass Password
    u1 := uuid.NewV4()

    pass.Id = u1.String()
    pass.Mobile = "111122"
    pass.Password = md5String("abc")

		// var bodyCustomer []Customer
		// if errIf := json.Unmarshal(body, &bodyCustomer); errIf != nil {
    //   panic(errIf)
		// }
    row, err := engine.Insert(&pass)

    fmt.Println(row, err)

    c.Set("data", pass)
	})

	router.PUT("/customer", func(c *gin.Context) {
    body, _ := ioutil.ReadAll(c.Request.Body)

		var bodyCustomer []Password
		if errIf := json.Unmarshal(body, &bodyCustomer); errIf != nil {
      panic(errIf)
		}

    c.Set("data", bodyCustomer)
	})

	router.DELETE("/customer", func(c *gin.Context) {
    body, _ := ioutil.ReadAll(c.Request.Body)

    var bodyCustomer []Password
		if errIf := json.Unmarshal(body, &bodyCustomer); errIf != nil {
      panic(errIf)
		}

    c.Set("data", "aa")
	})

	// router.PATCH("/cart", func(c *gin.Context) {
	// })

	router.GET("/customer", func(c *gin.Context) {
    var password []Password
    engine.SQL("select * from password").Find(&password)

    c.Set("data", password)
	})

  router.Run(":8080")
}
