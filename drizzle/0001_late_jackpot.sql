CREATE TABLE `codeScans` (
	`id` int AUTO_INCREMENT NOT NULL,
	`userId` int NOT NULL,
	`fileName` varchar(255) NOT NULL,
	`sourceCode` text NOT NULL,
	`securityScore` int NOT NULL DEFAULT 100,
	`riskLevel` enum('Critical','High','Medium','Low') NOT NULL DEFAULT 'Low',
	`vulnerabilityCount` int NOT NULL DEFAULT 0,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `codeScans_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `vulnerabilities` (
	`id` int AUTO_INCREMENT NOT NULL,
	`scanId` int NOT NULL,
	`type` varchar(100) NOT NULL,
	`severity` enum('Critical','High','Medium','Low') NOT NULL,
	`lineNumber` int NOT NULL,
	`columnNumber` int DEFAULT 0,
	`codeSnippet` text NOT NULL,
	`description` text,
	`recommendation` text,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `vulnerabilities_id` PRIMARY KEY(`id`)
);
