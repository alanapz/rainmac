static void delete_rule_number(RULESET*, unsigned, int*);
static int build_perm_mask(const RULESET*, const char*);
static int import_parse_subject(IOBUFF *buff, char **label, uid_t *uid, gid_t *gid);
static int import_parse_object(const RULESET*, IOBUFF*, RDATA**);

static int command_delete(RULESET *ruleset, IOBUFF* buff)
{
    char *rulenum_buff = iobuff_read_token(buff);
    if (!rulenum_buff)
    {
        return 0;
    }
    int ok = 0;
    unsigned rulenum = simple_strtoul(rulenum_buff, NULL, 10);
    if (rulenum > 0)
    {
        delete_rule_number(ruleset, rulenum, &ok);
    }
    kfree(rulenum_buff);
    return 1;
}

static void delete_rule_number(RULESET *ruleset, unsigned rule_number, int *ok)
{
    write_lock(&ruleset->lock);
    {
        RULE* rule = ruleset->head;
        while(rule && --rule_number > 0)
        {
            rule = rule->next;
        }
        if(rule)
        {
            delete_rule(rule);
            *ok = 1;
        }
    }
    write_unlock(&ruleset->lock);
}

static int command_insert(RULESET *ruleset, IOBUFF* buff, bool is_allow)
{
    char *perm_names = iobuff_read_token(buff);
    if (!perm_names)
    {
        return 0;
    }
    int perm_mask = build_perm_mask(ruleset, perm_names);
    if (perm_mask <= 0)
    {
        kfree(perm_names);
        return 0;
    }
    char *token = iobuff_read_token(buff);
    // If token is null, this must be a `star` type domain with no rdata
    if (!token)
    {
        add_rule(ruleset, is_allow, perm_mask, NULL);
        return 1;
    }
    char* label = NULL;
    int ok = 1; uid_t uid = -1; gid_t gid = -1;
    RDATA *rdata = NULL;
    while(ok)
    {
        ok = 0;
        if (!strcmp(token, "by"))
        {
            ok = import_parse_subject(buff, &label, &uid, &gid);
        }
        else if (!strcmp(token, "to") || !strcmp(token, "on"))
        {
            ok = import_parse_object(ruleset, buff, &rdata);
        }
        else
        {
            ok = 0;
        }
        if (ok && !(token = iobuff_read_token(buff)))
        {
            break;
        }
    }
    kfree(perm_names);
    kfree(token);
    if (!ok)
    {
        return ok;
    }
    RULE *rule = add_rule(ruleset, is_allow, perm_mask, rdata);
    if (label)
    {
        rule->label = label;
    }
    if (uid >= 0)
    {
        rule->uid = uid;
    }
    if (gid >= 0)
    {
        rule->gid = gid;
    }
    return ok;
}

static int build_perm_mask(const RULESET* ruleset, const char *perm_names)
{
    int access = 0;
    char *token;
    char *buff = copy_string(perm_names);
    while((token = strsep(&buff, ",")))
    {
        if (!strcmp(token, "all"))
        {
            kfree(buff);
            return (1 << ruleset->perm_count) - 1;
        }
        int i, index=0;
        for(i=0; i<ruleset->perm_count; i++)
        {
            if (!strcmp(token, ruleset->perm_names[i]))
            {
                index = 1;
                break;
            }
        }
        // Return error if permission name was not found in perm_names set for this ruleset
        if (!index)
        {
            kfree(buff);
            return 0;
        }
        access |= (1 << i);
    }
    kfree(buff);
    return access;
}

static int import_parse_subject(IOBUFF *buff, char **label, uid_t *uid, gid_t *gid)
{
    char *stype = iobuff_read_token(buff);
    if (!stype)
    {
        return 0;
    }
    int ok = 0;
    char *char_buff = NULL;
    if (!strcmp(stype, "label"))
    {
        char_buff = iobuff_read_token(buff);
        if (char_buff)
        {
            *label = kmalloc(strlen(char_buff)+1, GFP_KERNEL);
            strcpy(*label, char_buff);
            ok = 1;
        }
    }    
    else if (!strcmp(stype, "uid"))
    {
        char_buff = iobuff_read_token(buff);
        if (char_buff)
        {
            *uid = simple_strtol(char_buff, NULL, 10);
            if (*uid >= 0)
            {
                ok = 1;
            }
        }
    }    
    else if (!strcmp(stype, "gid"))
    {
        char_buff = iobuff_read_token(buff);
        if (char_buff)
        {
            *gid = simple_strtol(char_buff, NULL, 10);
            if (*gid >= 0)
            {
                ok = 1;
            }
        }
    }    
    kfree(stype);
    kfree(char_buff);
    return ok;
}

static int import_parse_object(const RULESET* ruleset, IOBUFF *buff, RDATA **rdata)
{
    char *obj_buff = iobuff_read_token(buff);
    if (!obj_buff)
    {
        return 0;
    }
    int ok = 0;
    if (ruleset->rdata_import)
    {
        if ((*rdata = ruleset->rdata_import(obj_buff)))
        {
            ok = 1;
        }
    }
    kfree(obj_buff);
    return ok;
}
