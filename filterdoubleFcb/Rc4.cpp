#include "rc4.h"

void rc4_setup( struct rc4_state *s, unsigned char *key,  int length )
{
    int  i, j, k;
    unsigned char  *m, a;

    s->x = 0;
    s->y = 0;
    m = s->m;

    for( i = 0; i < 256; i++ )
    {
        m[i] =(unsigned char) i;
    }

    j = k = 0;

    for( i = 0; i < 256; i++ )
    {
        a = m[i];
        j = (unsigned char) ( j + a + key[k] );
        m[i] = m[j]; m[j] = a;
        if( ++k >= length ) k = 0;
    }
}

void rc4_crypt( struct rc4_state *s, unsigned char *data, int length )
{ 
    int i, x, y;
    unsigned char  *m, a, b;

    x = s->x;
    y = s->y;
    m = s->m;

    for( i = 0; i < length; i++ )
    {
        x = (unsigned char) ( x + 1 ); 
		a = m[x];
        y = (unsigned char) ( y + a );
        m[x] = b = m[y];
        m[y] = a;
        data[i] ^= m[(unsigned char) ( a + b )];
    }

    s->x = x;
    s->y = y;
}

#ifdef TEST



int main( void )
{
    int i;
    struct rc4_state s;
    unsigned char buffer[30];

    printf( "\n RC4 Validation Tests:\n\n" );

    for( i = 0; i < 6; i++ )
    {
        printf( " Test %d ", i + 1 );

        memcpy( buffer, data[i], data_len[i] );

        rc4_setup( &s, &keys[i][1], keys[i][0] );
        rc4_crypt( &s, buffer, data_len[i] );

        if( memcmp( buffer, output[i], data_len[i] ) )
        {
            printf( "failed!\n" );
            return( 1 );
        }

        printf( "passed.\n" );
    }

    printf( "\n" );

    return( 0 );
}

#endif


