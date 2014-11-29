#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <microhttpd.h>
#include <strings.h>
#include <openssl/sha.h>

#define PORT 80
#define StrEq(a,b) (strcmp((a),(b))==0)
#define StrStartsWith(a,b) (strncmp((a),(b),strlen(b))==0)

const char HEX[] = "0123456789abcdef";
const char * __taken = "MyTokenIsVeryVeryVeryLong";

const size_t XMLBUFSIZ = 1024*4;

typedef int (*compar)(const void *, const void *);

struct WX_XML_Buff
{
    char * buff;
    size_t len;
};

struct WX_Signature
{
    char * token;
    char * timestamp;
    char * nonce;

    char * signature;
    char * echostr;
};

struct WX_Massage
{
    char * ToUserName;
    char * FromUserName;
    char * CreateTime;
    char * MsgType;
    char * MsgId;

    union {
        struct WX_Massage_Text
        {
            char * Content;
        } text;
    } data;
};

char * deepStrNCopy(const char* s,size_t len)
{
    char * ret = malloc(len+1);
    strncpy(ret,s,len);
    ret[len]='\0';
    return ret;
}

char * deepStrCopy(const char* s)
{
    if (s==NULL) return NULL;
    size_t len = strlen(s);
    char * ret = malloc(len+1);
    strcpy(ret,s);
    return ret;
}

#define deepFree(x) _deepFree((char**)(&(x)),sizeof(x)/sizeof(char*))
void _deepFree(char **s,size_t n)
{
    for (size_t i=0;i<n;++i)
        if (s[i]!=NULL)
        {
            free(s[i]);
            s[i]=NULL;
        }
}

char * ReadBetween(const char *xml,const size_t len,const char* tagb,const char* tage)
{
    size_t tlen= strlen(tagb);
    //char *p = strnstr(xml,tagb,len);
    char *p = strstr(xml,tagb);
    if (p==NULL) return NULL;
    //char *q = strnstr(xml,tage,len);
    char *q = strstr(xml,tage);
    if (q==NULL||p>q) return NULL;
    return deepStrNCopy(p+tlen,q-p-tlen);
}

size_t WriteBetween(char *ret,size_t len,const char* tagb,const char* tage,const char * data)
{
    size_t a = strlen(tagb),b = strlen(tage),c = strlen(data);
    if (a+b+c<=len)
    {
        strcat(ret,tagb);
        strcat(ret,data);
        strcat(ret,tage);
        return len-a-b-c;
    }
    return 0;
}

int SaveSignature (struct WX_Signature *cls,enum MHD_ValueKind kind,const char *key, const char *value)
{
    if (strcmp(key,"signature")==0) cls->signature=deepStrCopy(value);
    if (strcmp(key,"timestamp")==0) cls->timestamp=deepStrCopy(value);
    if (strcmp(key,"nonce")==0) cls->nonce=deepStrCopy(value);
    if (strcmp(key,"echostr")==0) cls->echostr=deepStrCopy(value);
    return MHD_YES;
}

int WX_checkSignature(struct MHD_Connection *connection,struct WX_Signature *sig)
{

    MHD_get_connection_values(connection,MHD_GET_ARGUMENT_KIND,(MHD_KeyValueIterator)SaveSignature,sig);
    if ( !sig->signature || !sig->nonce || !sig->timestamp)
        return 1;
    sig->token = deepStrCopy(__taken);

    char **xsig =(void**)sig;
    qsort(xsig,3,sizeof(char*),(compar)strcmp);

    SHA_CTX ctx;
    SHA1_Init(&ctx);
    for (int i=0;i<3;++i)
        SHA1_Update(&ctx,xsig[i],strlen(xsig[i]));
    unsigned char hash[SHA_DIGEST_LENGTH*2];
    SHA1_Final(hash, &ctx);
    for (int i=SHA_DIGEST_LENGTH-1;i>=0;--i)
    {
        hash[i*2+1]=HEX[hash[i]&15];
        hash[i*2]=HEX[hash[i]>>4];
    }
    return strncmp(hash,sig->signature,SHA_DIGEST_LENGTH);
}

void ReadWXMassage(const char xml[],const size_t len,struct WX_Massage * msg)
{
    msg->ToUserName = ReadBetween(xml,len,"<ToUserName><![CDATA[","]]></ToUserName>");
    msg->FromUserName = ReadBetween(xml,len,"<FromUserName><![CDATA[","]]></FromUserName>");
    msg->CreateTime = ReadBetween(xml,len,"<CreateTime>","</CreateTime>");
    msg->MsgType = ReadBetween(xml,len,"<MsgType><![CDATA[","]]></MsgType>");
    msg->MsgId = ReadBetween(xml,len,"<MsgId>","</MsgId>");
    if (0==strcmp(msg->MsgType,"text"))
    {
        msg->data.text.Content = ReadBetween(xml,len,"<Content><![CDATA[","]]></Content>");
    }
}

size_t WriteWXMassage(char ret_buff[],size_t len,const struct WX_Massage *msg)
{
    if (len>=5)
    {
        strcat(ret_buff,"<xml>");
        len -=5;
    }
    len=WriteBetween(ret_buff,len,"<ToUserName><![CDATA[","]]></ToUserName>",msg->ToUserName);
    len=WriteBetween(ret_buff,len,"<FromUserName><![CDATA[","]]></FromUserName>",msg->FromUserName);
    len=WriteBetween(ret_buff,len,"<CreateTime>","</CreateTime>",msg->CreateTime);
    len=WriteBetween(ret_buff,len,"<MsgType><![CDATA[","]]></MsgType>",msg->MsgType);
    //Don't need MsgId
    if (0==strcmp(msg->MsgType,"text"))
    {
        len=WriteBetween(ret_buff,len,"<Content><![CDATA[","]]></Content>",msg->data.text.Content);
    }
    if (len>=6)
    {
        strcat(ret_buff,"</xml>");
        len -= 6;
    }
    return len;
}

void WX_Text_Header(const struct WX_Massage *req,struct WX_Massage *resp)
{
    resp->MsgType = deepStrCopy("text");
    if (StrStartsWith(req->data.text.Content,"qp"))
    {
        resp->data.text.Content = deepStrCopy("ni zai qiang pao");
        return ;
    }
    resp->data.text.Content = deepStrCopy("wo bu zhi dao");
}

static int
WX_Server_Main (void *cls, struct MHD_Connection *connection,
                const char *url, const char *method,
                const char *version, const char *upload_data,
                size_t *upload_data_size, void **con_cls)
{
    struct MHD_Response *response;
    int ret = -1;
    //    printf ("New %s request for %s using version %s\n", method, url, version);

    if (StrStartsWith(url,"/wx_api"))
    {

        struct WX_Signature sig;
        bzero(&sig,sizeof(struct WX_Signature));

        if (WX_checkSignature(connection,&sig))
        {
            const char *page = "<html><body>BAD_REQUEST</body></html>";
            response = MHD_create_response_from_buffer (strlen (page), (void *) page,MHD_RESPMEM_PERSISTENT);
            ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, response);
            MHD_destroy_response (response);
            deepFree(sig);
            return ret;
        }

        if (StrEq(method,"GET"))
        {
            response = MHD_create_response_from_buffer(strlen(sig.echostr),(void *) sig.echostr,MHD_RESPMEM_MUST_COPY);
            ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
            MHD_destroy_response(response);
            deepFree(sig);
            return ret;
        }

        deepFree(sig);

        //WX Post
        if (StrEq(method,"POST"))
        {
            struct WX_Massage massage;
            bzero(&massage,sizeof(struct WX_Massage));

            struct WX_Massage ret_msg;
            bzero(&ret_msg,sizeof(struct WX_Massage));

            struct WX_XML_Buff *post_buff;
            if (*con_cls==NULL)
            {
                post_buff = (*con_cls) = malloc(sizeof(struct WX_XML_Buff));
                bzero(*con_cls,sizeof(struct WX_XML_Buff));
                post_buff->buff = malloc(XMLBUFSIZ);
                post_buff->len = 0;
                return MHD_YES;
            }
            else
                post_buff =(struct WX_XML_Buff *)(*con_cls);

            //        printf("%s",upload_data);

            if (*upload_data_size != 0)
            {
                if (post_buff->len + *upload_data_size<XMLBUFSIZ)
                {
                    memcpy(post_buff->buff+post_buff->len,upload_data,*upload_data_size);
                    post_buff->len += *upload_data_size;
                    *upload_data_size = 0;
                    return MHD_YES;
                }
                else
                    return MHD_NO;
            }
            else
            {
                post_buff->buff[post_buff->len]='\0';

                ReadWXMassage(post_buff->buff,post_buff->len,&massage);

                ret_msg.FromUserName = deepStrCopy(massage.ToUserName);
                ret_msg.ToUserName = deepStrCopy(massage.FromUserName);
                ret_msg.CreateTime = deepStrCopy(massage.CreateTime);

                if (strcmp(massage.MsgType,"text")==0)
                    WX_Text_Header(&massage,&ret_msg);

                char *buff=malloc(XMLBUFSIZ+1);
                buff[0]='\0';
                WriteWXMassage(buff,XMLBUFSIZ,&ret_msg);
                buff[XMLBUFSIZ]='\0';

                response = MHD_create_response_from_buffer(strlen(buff),(void *) buff,MHD_RESPMEM_MUST_FREE);
                ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
                MHD_destroy_response(response);

                deepFree(massage);
                deepFree(ret_msg);
                return ret;
            }
        }
    }

    // 404 Not Found
    const char *page = "<html><body><h1>404 NOT FOUND</h1></body></html>";
    response = MHD_create_response_from_buffer (strlen (page), (void *) page,MHD_RESPMEM_PERSISTENT);
    ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
    MHD_destroy_response (response);

    return ret;
}

int main ()
{
    struct MHD_Daemon *daemon;

    daemon = MHD_start_daemon (MHD_USE_POLL_INTERNALLY | MHD_USE_DEBUG, PORT, NULL, NULL,
                               &WX_Server_Main, NULL, MHD_OPTION_END);
    if (NULL == daemon)
        return 1;

    getchar ();

    MHD_stop_daemon (daemon);
    return 0;
}
