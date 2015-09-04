
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied
ALTER TABLE `registrations` MODIFY `jwk` blob NOT NULL;



-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back
ALTER TABLE `registrations` MODIFY `jwk` mediumblob NOT NULL;
