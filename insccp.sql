/*
 Navicat Premium Data Transfer

 Source Server         : localhost_3306
 Source Server Type    : MySQL
 Source Server Version : 80019
 Source Host           : localhost:3306
 Source Schema         : insccp

 Target Server Type    : MySQL
 Target Server Version : 80019
 File Encoding         : 65001

 Date: 19/05/2021 20:20:23
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for friendlist
-- ----------------------------
DROP TABLE IF EXISTS `friendlist`;
CREATE TABLE `friendlist`  (
  `srcid` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `dstid` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of friendlist
-- ----------------------------
INSERT INTO `friendlist` VALUES ('Lenin_Forever', 'Marx');
INSERT INTO `friendlist` VALUES ('StalinGreat', 'Lenin_Forever');
INSERT INTO `friendlist` VALUES ('Lenin_Forever', 'StalinGreat');

-- ----------------------------
-- Table structure for userinfo
-- ----------------------------
DROP TABLE IF EXISTS `userinfo`;
CREATE TABLE `userinfo`  (
  `id` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `password` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL,
  `nickName` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of userinfo
-- ----------------------------
INSERT INTO `userinfo` VALUES ('Lenin_Forever', 'd9ab5e53593042c376730c64d1fc6786b53f71a291630204', '十月的炮声');
INSERT INTO `userinfo` VALUES ('StalinGreat', 'd9ab5e53593042c376730c64d1fc6786b53f71a291630204', '钢铁大师');
INSERT INTO `userinfo` VALUES ('Tzedong_Mao', 'd9ab5e53593042c376730c64d1fc6786b53f71a291630204', '东方之舵手');

SET FOREIGN_KEY_CHECKS = 1;
