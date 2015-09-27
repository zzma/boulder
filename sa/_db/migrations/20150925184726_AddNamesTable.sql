
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

CREATE TABLE `issuedNames` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `reversedName` varchar(1024) NOT NULL,
  `serial` varchar(255) NOT NULL,
  `LockCol` bigint(20) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `serial_Idx` (`serial`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

DROP TABLE `issuedNames`;
