const router = require("express").Router();
const {
  usernameVarmi,
  rolAdiGecerlimi,
  checkPayload,
} = require("./auth-middleware");
const { JWT_SECRET } = require("../secrets"); // bu secret'ı kullanın!
const jwt = require("jsonwebtoken");
const bcryptjs = require("bcryptjs");
const userModel = require("../users/users-model");

router.post(
  "/register",
  rolAdiGecerlimi,
  checkPayload,
  async (req, res, next) => {
    /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status: 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
    try {
      let hashedPassword = bcryptjs.hashSync(req.body.password);
      let userRequestModel = {
        username: req.body.username,
        password: hashedPassword,
        role_name: req.body.role_name,
      };
      const registeredUser = await userModel.ekle(userRequestModel);
      res.status(201).json(registeredUser);
    } catch (error) {
      next(error);
    }
  }
);

router.post("/login", usernameVarmi, checkPayload, (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status: 200
    {
      "message": "sue geri geldi!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    Token 1 gün sonra timeout olmalıdır ve aşağıdaki bilgiyi payloadında içermelidir:

    {
      "subject"  : 1       // giriş yapan kullanıcının user_id'si
      "username" : "bob"   // giriş yapan kullanıcının username'i
      "role_name": "admin" // giriş yapan kulanıcının role adı
    }
   */
  try {
    let payload = {
      subject: req.currentUser.user_id,
      username: req.currentUser.username,
      role_name: req.currentUser.role_name,
    };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "1d" });
    res.json({
      message: `${req.currentUser.username} geri döndüğüne çok memnun olduk!`,
      token: token,
    });
  } catch (error) {
    next(error);
  }
});

module.exports = router;
