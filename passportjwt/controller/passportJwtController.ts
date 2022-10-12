import jwt from "jsonwebtoken";
import index from "config/env";
import { Router, Response, Request } from "express";
import { api } from "constants/api";
import dynamoConnect from "../../../models/dynamodb";
import { dynamoTable } from "constants/dynamoTable";
const bcrypt = require("bcrypt-nodejs");

const passportJwtRouter = Router();
const generateJWTToken = (id) =>
  jwt.sign({ id }, index.JWT_SECRET, { expiresIn: index.JWT_EXPIRES_IN });

passportJwtRouter.post(
  api.passportJwtLogin,
  async (req: Request, res: Response) => {
    try {
      const { id, password } = req.body;

      const User = await dynamoConnect.query({
        TableName: dynamoTable.admin,
        KeyConditionExpression: "#id = :id",
        ExpressionAttributeNames: { "#id": "id" },
        ExpressionAttributeValues: { ":id": id },
      });
      if (
        User?.Items[0] &&
        bcrypt.compareSync(password + User?.Items[0].salt, User?.Items[0].pw)
      ) {
        return res.send({
          status: 200,
          result: {
            id,
            token: generateJWTToken(req.body.id),
            role: User?.Items[0].role,
            name: User?.Items[0].name,
          },
        });
      }

      return res.status(400).send({ message: "invalid user data" });
    } catch (message) {
      return res.status(400).send({ message });
    }
  }
);

export default passportJwtRouter;
