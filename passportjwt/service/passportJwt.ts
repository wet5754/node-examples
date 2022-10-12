import passport from "passport";
import index from "config/env";
import { Strategy as JwtStrategy, ExtractJwt } from "passport-jwt";
import { response } from "config/apiResponse";
import dynamoConnect from "../../../models/dynamodb";
import { dynamoTable } from "constants/dynamoTable";

export const passportJwt = (app) => {
  const jwtOptions = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: index.JWT_SECRET,
  };

  const verifyUser = async (user, done) => {
    const User = await dynamoConnect.query({
      TableName: dynamoTable.admin,
      KeyConditionExpression: "#id = :id",
      ExpressionAttributeNames: { "#id": "id" },
      ExpressionAttributeValues: { ":id": user.id },
    });

    if (User.Items && User.Items.length > 0) done(null, user);
    else done(null, false);
  };

  passport.use(new JwtStrategy(jwtOptions, verifyUser));
  app.use(passport.initialize());

  /* api 공통 미들웨어 적용 */
  const passportJwtAuth = (req, res, next) => {
    passport.authenticate("jwt", { session: false }, (_, user) => {
      if (user) {
        req.user = user;
        next();
      } else {

      /* jwt 인증 에러 */
        res.send(
          response({
            status: 301,
            error: { message: "TokenExpiredError" },
          })
        );
      }
    })(req, res, next);
  };
  app.use("/v1/api/*", passportJwtAuth, (req, res, next) => next());
};
