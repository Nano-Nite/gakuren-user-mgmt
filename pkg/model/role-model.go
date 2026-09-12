package model

import (
	"time"

	"github.com/google/uuid"
)

type RoleModel struct {
	UUID        uuid.UUID  `db:"uuid"`
	Name        string     `db:"name"`
	AbbrName    string     `db:"abbr_name"`
	StatusUUID  uuid.UUID  `db:"status_uuid"`
	Level       int        `db:"level"`
	CreatedDate time.Time  `db:"created_date"`
	UpdatedDate *time.Time `db:"updated_date"`
}

type PermissionModel struct {
	UUID        uuid.UUID  `db:"uuid"`
	MenuUUID    uuid.UUID  `db:"menu_uuid"`
	Name        string     `db:"name"`
	Code        string     `db:"code"`
	StatusUUID  uuid.UUID  `db:"status_uuid"`
	CreatedDate time.Time  `db:"created_date"`
	UpdatedDate *time.Time `db:"updated_date"`
}

type MenuModel struct {
	UUID        uuid.UUID  `db:"uuid"`
	Parent      uuid.UUID  `db:"parent"`
	Name        string     `db:"name"`
	Code        string     `db:"code"`
	Order       int        `db:"order"`
	StatusUUID  uuid.UUID  `db:"status_uuid"`
	CreatedDate time.Time  `db:"created_date"`
	UpdatedDate *time.Time `db:"updated_date"`
}

type ResultMenuModel struct {
	UUID       uuid.UUID `db:"uuid"`
	Name       string    `db:"name"`
	Parent     *string   `db:"parent"`
	Permission []string  `db:"permission"`
}
