import express, { Express, NextFunction, Request, Response } from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import compression from "compression";
import corsOptions from "./config/corsOptions";
import path from "path";
import authRoutes from "./routes/auth.routes";
import mongoose from "mongoose";
import { NODE_ENV, PORT, DB_HOST } from "./secrets";
import { HttpException } from "./exceptions";
import { fileURLToPath } from "url";


// @ts-ignore
// const __filename = fileURLToPath(import.meta.url);
// const __dirname = path.dirname(__filename);

function startServer() {
  const app: Express = express();

  // Middleware
  app.use(cors(corsOptions));
  app.use(compression());
  app.use(cookieParser());
  app.use(express.json());

  // Static Files
  // app.use(express.static(path.join(__dirname, "assets")));

  // Routes
  app.use("/api/auth", authRoutes);

  // 404
  app.all("*", (req: Request, res: Response) => {
    res.status(404);
    if (req.accepts("json")) {
      res.json({
        message: "404 Not Found",
      });
    } else {
      res.type("txt").send("404 Not Found");
    }
  });

  // Error handler
  app.use(
    (err: HttpException, req: Request, res: Response, next: NextFunction) => {
      const statusCode = err.statusCode || 500;
      const message = err.message || "Internal Server Error";
      res
        .status(statusCode)
        .json({ success: false, statusCode, message, isError: true });
    }
  );

  app.listen(PORT, () =>
    console.log(
      `Listening on ${
        NODE_ENV === "production"
          ? "https://demo7.isaccobertoli.com"
          : `http://localhost:${PORT}`
      }`
    )
  );
}

// Connect to MongoDB
console.log(`Connecting to ${DB_HOST}`);
mongoose
  .connect(DB_HOST)
  .then(() => {
    console.log("Database connected");
    startServer();
  })
  .catch((err) => {
    console.log("Database connection error");
    console.log(err);
  });
