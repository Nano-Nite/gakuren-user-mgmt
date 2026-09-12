package helper

import (
	"gakuren-system.com/pkg/db"
	"gakuren-system.com/pkg/model"
)

func GetRoleByUUID(uuid string) (*model.StatusModel, error) {
	selectedData, err := db.GetSingleDataByQuery[model.StatusModel]("select * from user_sch.role where uuid = $1", uuid)
	if err != nil {
		return nil, err
	}

	return selectedData, nil
}

func GetUserRolePermissionCodeList(uuid string) (*[]string, error) {
	selectedData, err := db.GetMultipleDataByQuery[model.PermissionModel](`
	SELECT p.code FROM user_sch.user u
		JOIN user_sch.role r on u.role_uuid = r.uuid
		JOIN user_sch.role_permission rp on r.uuid = rp.role_uuid
		JOIN user_sch.permission p on rp.permission_uuid = p.uuid
		LEFT JOIN user_sch.menu m on m.uuid = p.menu_uuid
	WHERE u.uuid = $1
	GROUP BY p.code, m.order
	ORDER BY m.order asc;
	`, uuid)
	if err != nil {
		return nil, err
	}

	result := make([]string, len(*selectedData))
	for i, permission := range *selectedData {
		result[i] = permission.Code
	}

	return &result, nil
}

func GetUserMenuList(uuid string) (*[]string, error) {
	selectedData, err := db.GetMultipleDataByQuery[model.MenuModel](`
	SELECT m.name FROM user_sch.user u
		JOIN user_sch.role r on u.role_uuid = r.uuid
		JOIN user_sch.role_permission rp on r.uuid = rp.role_uuid
		JOIN user_sch.permission p on rp.permission_uuid = p.uuid
		JOIN user_sch.menu m on m.uuid = p.menu_uuid
	WHERE u.uuid = $1
	GROUP BY m.name, m.order
	ORDER BY m.order asc;
	`, uuid)
	if err != nil {
		return nil, err
	}

	result := make([]string, len(*selectedData))
	for i, permission := range *selectedData {
		result[i] = permission.Name
	}

	return &result, nil
}

func UserMenuIntegeration(userUUID string) (map[string]interface{}, error) {
	selectedData, err := db.GetMultipleDataByQuery[model.ResultMenuModel](`
	SELECT 
		m."uuid" 
		,m.name name
		,(select m2.name from user_sch.menu m2 where m.parent = m2.uuid) as parent
		,array_agg(p.code) permission
	FROM user_sch.user u
		JOIN user_sch.role r on u.role_uuid = r.uuid
		JOIN user_sch.role_permission rp on r.uuid = rp.role_uuid
		JOIN user_sch.permission p on rp.permission_uuid = p.uuid
		JOIN user_sch.menu m on m.uuid = p.menu_uuid
	WHERE u.uuid = $1
	GROUP BY m.name, m.uuid
	ORDER BY parent desc, m.order asc, name asc;
	`, userUUID)
	if err != nil {
		return nil, err
	}

	menus := make(map[string]interface{}, 0)

	for _, v := range *selectedData {
		if v.Parent == nil {
			body := make(map[string]interface{})

			body["child"] = []string{}
			body["permission"] = v.Permission
			menus[v.Name] = body
		} else {
			body := menus[*v.Parent].(map[string]interface{})

			body["child"] = append(body["child"].([]string), v.Name)
			body["permission"] = append(body["permission"].([]string), v.Permission...)
		}

	}

	return menus, nil
}
