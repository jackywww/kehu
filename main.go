package main

import (
  "github.com/gin-gonic/gin"
  "github.com/go-playground/validator/v10"
  "github.com/satori/go.uuid"
  "github.com/dgrijalva/jwt-go"
  //"github.com/dgrijalva/jwt-go/request"
  //"github.com/micro/go-micro/config"
  _ "github.com/lib/pq"
  "github.com/go-xorm/xorm"
  "github.com/jinzhu/configor"
  "encoding/json"
	"io/ioutil"
	"fmt"
	"net/http"
  "crypto/md5"
  "io"
  "time"
  "strings"
  "regexp"
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
  Mobile string `json:"mobile" required:"true" validate:"required"`
  Password string `json:"password,omitempty" validate:"required"`
}

type Login struct {
  Mobile string `json:"mobile" validate:"required"`
  Password string `json:"password" validate:"required"`
}

type Token struct {
	Token string `json:"token"`
}

var Config = struct {
  Db struct {
    Engine string `default:"postgres"`
    Host  string `default:"localhost"`
    Name     string
    User     string `default:"root"`
    Password string `required:"true"`
    Port     uint   `default:"5432"`
    Sslmode string `default:"disable"`
  }
  Rsa struct {
    PublicKeyPath string
    PrivateKeyPath string
    Iss string `default:"Jacky"`
    Exp int `default:"1"`
    SigningMethod string `default:"RS512"`
  }
}{}

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

func getTokenString(id string)(tokenString string) {
  if Config.Rsa.PrivateKeyPath == "" {
    panic("Please config private key path!")
  }

  privateKey, err := ioutil.ReadFile(Config.Rsa.PrivateKeyPath)
  if err != nil {
      panic(err)
  }

  claims := &jwt.StandardClaims{
                ExpiresAt: time.Now().Add(time.Hour * time.Duration(Config.Rsa.Exp)).Unix(),
                Issuer:    Config.Rsa.Iss,
                Id: id,
        }

  method := jwt.GetSigningMethod(Config.Rsa.SigningMethod)
  token := jwt.NewWithClaims(method, claims)

  var privateKeyString interface{}
  if strings.Index(Config.Rsa.SigningMethod, "HS") > -1 {
    privateKeyString = privateKey
  } else {
    privateKeyString, err = jwt.ParseRSAPrivateKeyFromPEM(privateKey)
    if err != nil {
      panic(err)
    }
  }

  tokenString, err = token.SignedString(privateKeyString)
  if err != nil {
    panic(err)
  }

  return tokenString
}

func parseAndVertifyToken(tokenString string)(token *jwt.Token, e error){
  publicKey, err := ioutil.ReadFile(Config.Rsa.PublicKeyPath)
  if err != nil {
    panic(err)
  }

  var publicKeyString interface{}
  if strings.Index(Config.Rsa.SigningMethod, "HS") > -1 {
    publicKeyString = publicKey
  } else {
    publicKeyString, err = jwt.ParseRSAPublicKeyFromPEM(publicKey)
    if err != nil {
      panic(err)
    }
  }

  token, err = jwt.ParseWithClaims(tokenString, jwt.MapClaims{}, func(token *jwt.Token) (i interface{}, e error) {
      return publicKeyString, nil
  })
  if err != nil {
    return nil, err
  }

  return token, err
}

//mobile verify
func VerifyMobileFormat(mobileNum string) bool {
	regular := "^((13[0-9])|(14[5,7])|(15[0-3,5-9])|(17[0,3,5-8])|(18[0-9])|166|198|199|(147))\\d{8}$"

	reg := regexp.MustCompile(regular)
	return reg.MatchString(mobileNum)
}

func validateLoginStruct(item Login) {
  err := validate.Struct(item)

	if err != nil {
    //errInfo(err)
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

func validatePasswordStruct(item Password) {
  err := validate.Struct(item)

	if err != nil {
    //errInfo(err)
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

func main() {
  configor.Load(&Config, "config.yml")
  psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",Config.Db.Host, Config.Db.Port, Config.Db.User, Config.Db.Password, Config.Db.Name, Config.Db.Sslmode)
  engine, _ = xorm.NewEngine(Config.Db.Engine, psqlInfo)

  //gin.SetMode(gin.ReleaseMode)
  router := gin.Default()
	router.Use(errHandler())
	router.Use(responseHandler())
  validate = validator.New()

	router.POST("/customer", func(c *gin.Context) {
    body, _ := ioutil.ReadAll(c.Request.Body)
    var bodyCustomer, pass Password
		if errIf := json.Unmarshal(body, &bodyCustomer); errIf != nil {
      panic(errIf)
		}

    validatePasswordStruct(bodyCustomer)
    if VerifyMobileFormat(bodyCustomer.Mobile) == false {
      panic("Mobile format error!")
    }

    u1 := uuid.NewV4()

    pass.Id = u1.String()
    pass.Mobile = bodyCustomer.Mobile
    pass.Password = md5String(bodyCustomer.Password)

    row, err := engine.Insert(&pass)
    if err != nil {
      panic(err)
    }
    if row == 0 {
      panic("Insert Fail!")
    }

    pass.Password = ""
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

  router.POST("/customer/login", func(c *gin.Context) {
    body, _ := ioutil.ReadAll(c.Request.Body)

		var bodyCustomer Login
		if errIf := json.Unmarshal(body, &bodyCustomer); errIf != nil {
      panic(errIf)
		}
    validateLoginStruct(bodyCustomer)
    if VerifyMobileFormat(bodyCustomer.Mobile) == false {
      panic("Mobile format error!")
    }

    cols := []string{"id", "mobile", "password"}
    var user Password
    var valuesMap = make(map[string]string)
    if has, _ := engine.Table(&user).Where("mobile = ?", bodyCustomer.Mobile).Cols(cols...).Get(&valuesMap); has {
      if valuesMap["password"] != md5String(bodyCustomer.Password) {
        c.Set("data", gin.H{"token": nil})
        return
      }
    }

    tokenString := getTokenString(valuesMap["id"])
    // token, err := parseAndVertifyToken(tokenString)
    // if err != nil {
    //   panic(err)
    // }
    //
    // aaaaa := token.Claims.(jwt.MapClaims)
    // aaaaa["token"] = tokenString

    c.SetCookie("token", tokenString, -1, "/", "localhost", false, true)
    c.Set("data", gin.H{"token": tokenString})
	})

  router.Run(":8081")
}
